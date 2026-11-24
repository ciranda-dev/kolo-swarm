package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	kolosecure "github.com/ciranda-dev/kolo-secure"
	"github.com/ciranda-dev/kolo-swarm/internal/backoff"
)

// Connect's refusals that are not a wait.
var (
	errFull      = fmt.Errorf("%w: limit reached", ErrRefused)
	errTopicLeft = fmt.Errorf("%w: topic left", ErrRefused)
)

// failure is a Connect backoff of an address or of a key at one address.
type failure struct {
	fails int
	next  time.Time
}

// pair is a key at one address.
type pair struct {
	k    key
	addr netip.AddrPort
}

// connectDial is a Connect dial whose key has not proved itself yet. It holds a place in MaxPeers, MaxConnectPeers
// and its topic but no slot, so a false address for a key never stands in the way of that key.
type connectDial struct {
	topic   Topic
	vouched bool // lookups found the key at the address
	cancel  context.CancelFunc
}

// How a Connect dial or hello ended, for its backoff.
const (
	connectQuiet    = iota // canceled, closed, left, or refused before anything was sent
	connectUnproved        // no answer or a timeout before the key proved itself
	connectWrongKey        // another key answered
	connectDeadline        // the caller's deadline ended it
	connectProved          // failed after the key proved itself
)

// Connect dials pub at addr, which the peer at from supplied (zero: unknown, so global addresses only), and runs the
// hello for topic; it returns nil once this dial's connection is admitted. Errors: ErrInvalidArgument for unusable
// arguments, ErrRefused for Allow, a limit or the peer (ErrWait when a backoff, the dial rate or dials in progress
// refuse it for now), ErrDuplicate when the key already has a place or a hello, or a Connect dial at addr, and ErrLost
// when the dial fails (wrapping kolosecure.ErrUnexpectedPeer when another key answered). See the guide for the rest.
func (s *Swarm) Connect(ctx context.Context, topic Topic, pub ed25519.PublicKey, addr netip.AddrPort, from netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch {
	case len(pub) != ed25519.PublicKeySize || bytes.Equal(pub, s.key):
		return fmt.Errorf("%w: Connect needs another 32-byte key", ErrInvalidArgument)
	case addr.Addr().Is6():
		return errIPv6("address")
	case from.IsValid() && !from.Is4():
		return errIPv6("from address")
	case addr.Port() == 0 || !reachableFrom(from, connectScope)(addr.Addr()):
		return fmt.Errorf("%w: Connect needs an IPv4 address and port in the scope of from", ErrInvalidArgument)
	case s.ownAddr(addr):
		return fmt.Errorf("%w: Connect to our own address", ErrInvalidArgument)
	}
	s.mu.Lock()
	err := s.joinedErrLocked(topic)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if !s.allow(pub, addr) {
		return fmt.Errorf("%w: Allow", ErrRefused)
	}
	k, pr := key(pub), pair{key(pub), addr}
	dctx, cancel := mergeCtx(ctx, s.ctx)
	defer cancel()
	d, err := s.reserveConnect(pr, topic, cancel)
	if err != nil {
		return err
	}
	var c *kolosecure.Conn
	var sl *slot  // the place the proved connection runs its hello for
	held := false // a hello of k on c counted in helloKey
	defer func() {
		if s.hooks.beforeCleanup != nil {
			s.hooks.beforeCleanup()
		}
		if held {
			c.CloseWithError(codeNormal, "")
		}
		s.mu.Lock()
		if held {
			s.dropHelloKeyLocked(k)
		}
		s.dropDialLocked(pr, d)
		if sl != nil {
			sl.reserved = false
		}
		s.mu.Unlock()
		if sl != nil {
			// A no-op once the slot was released or admitted; it frees the slot after a panic.
			s.releaseConnect(k, sl, topic, addr, connectQuiet, releaseQuiet)
		}
		s.poke()
	}()
	c, err = s.dialDirect(dctx, addr, pub)
	if err != nil {
		refused := errors.Is(err, kolosecure.ErrInvalidArgument) || exhausted(err)
		end := connectUnproved
		switch {
		case refused:
			end = connectQuiet
		case errors.Is(err, kolosecure.ErrUnexpectedPeer):
			end = connectWrongKey
		case dctx.Err() != nil:
			end = canceledEnd(ctx)
		}
		s.endDial(pr, end, refused)
		return s.connectErr(ctx, topic, err, dctx.Err() != nil)
	}
	s.mu.Lock()
	s.dropDialLocked(pr, d)
	old, closed := s.slots[k], s.closed
	switch {
	case closed || s.helloKey[k] >= helloPerKey:
	case old != nil && old.peer != nil && !old.peer.direct && s.relays != nil && !old.reserved:
		// As in dialVia, a direct connection replaces a relayed one in its place, reserved for the hello since the
		// other side may close the relayed one first; another Connect's place stays its.
		sl = old
		sl.reserved = true
	case old == nil:
		// The key proved itself: the dial's place becomes its reserved slot, which MaxPeers, MaxConnectPeers and the
		// topic already counted.
		sl = &slot{topic: topic, own: addr.Addr(), connect: true, reserved: true}
		s.slots[k] = sl
	}
	if sl != nil {
		s.helloKey[k]++
		held = true
	}
	s.mu.Unlock()
	if sl == nil {
		c.CloseWithError(codeDuplicate, "")
		if closed {
			return ErrClosed
		}
		return ErrDuplicate
	}
	err = s.handshakeFor(dctx, c, k, false, true, sl, []Topic{topic})
	s.mu.Lock()
	s.dropHelloKeyLocked(k)
	held = false
	taken := s.slots[k] == sl && sl.peer != nil
	left := !s.joinedLocked(topic)
	if err == nil {
		delete(s.endFails, addr)
		delete(s.pairFails, pr)
	}
	s.mu.Unlock()
	if err != nil {
		end := connectProved
		if dctx.Err() != nil {
			end = canceledEnd(ctx)
		}
		s.releaseConnect(k, sl, topic, addr, end, helloRelease(err))
	}
	switch {
	case err == nil:
		return nil
	case s.ctx.Err() != nil:
		return ErrClosed
	case ctx.Err() != nil:
		return ctx.Err()
	case taken:
		// Another connection of the key won the hello.
		return ErrDuplicate
	case left:
		return errTopicLeft
	}
	return err
}

// joinedErrLocked returns ErrClosed, or ErrInvalidArgument when Connect cannot use topic. Call with mu held.
func (s *Swarm) joinedErrLocked(topic Topic) error {
	if s.closed {
		return ErrClosed
	}
	if t := s.topics[topic]; t == nil || t.joining {
		return fmt.Errorf("%w: Connect needs a joined topic", ErrInvalidArgument)
	}
	return nil
}

// canceledEnd is how a Connect dial or hello whose context ended counts: the caller's deadline is a failure, so a
// short deadline cannot redial a silent address at once; a cancel, Leave or Close counts for nothing.
func canceledEnd(ctx context.Context) int {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return connectDeadline
	}
	return connectQuiet
}

// connectScope is scopeOf with the carrier-grade NAT range apart from the private ranges, so a peer in one cannot
// point the swarm into the other.
func connectScope(ip netip.Addr) int {
	if cgnat.Contains(ip) {
		return scopeCGNAT
	}
	return scopeOf(ip)
}

// ownAddr reports whether addr is the node's socket. A public address a NAT maps to it is not known here.
func (s *Swarm) ownAddr(addr netip.AddrPort) bool {
	ua, ok := s.node.Addr().(*net.UDPAddr)
	return ok && isOwn(ua.AddrPort(), addr, net.InterfaceAddrs)
}

// isOwn reports whether addr is local, or, when local listens on every address, a loopback or interface address
// (from ifaces) at its port.
func isOwn(local, addr netip.AddrPort, ifaces func() ([]net.Addr, error)) bool {
	ip := local.Addr().Unmap()
	switch {
	case addr.Port() != local.Port():
		return false
	case addr.Addr() == ip:
		return true
	case !ip.IsUnspecified():
		return false
	case addr.Addr().IsLoopback():
		return true
	}
	as, err := ifaces()
	if err != nil {
		return false
	}
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if x, ok := netip.AddrFromSlice(n.IP); ok && x.Unmap() == addr.Addr() {
				return true
			}
		}
	}
	return false
}

// vouchedHistoryLocked returns k's own history when lookups found k at addr (its candidate's record, or the last
// record kept in past), else nil. A zero addr, a relayed peer's, is never vouched. Call with mu held.
func (s *Swarm) vouchedHistoryLocked(k key, addr netip.AddrPort) *history {
	if c := s.cands[k]; c != nil {
		if c.rec.Addr == addr {
			return &c.history
		}
		return nil
	}
	if h := s.past[k]; h != nil && h.addr.IsValid() && h.addr == addr {
		return h
	}
	return nil
}

// reserveConnect takes a place for a Connect dial of pr, within the bounds of a dial from a lookup and its own. The
// limits come first: they end only when peers leave or the configuration changes, so they are never ErrWait. At an
// address lookups vouched for, the address's backoff, the host's wait and the dials to it that no lookup vouched for
// do not apply, so a third party's dials never hold the key off; still, at most one such dial runs per host, since a
// server can forge records.
func (s *Swarm) reserveConnect(pr pair, topic Topic, cancel context.CancelFunc) (*connectDial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, k, host := time.Now(), pr.k, pr.addr.Addr()
	if err := s.joinedErrLocked(topic); err != nil {
		return nil, err
	}
	if s.slots[k] != nil || s.helloKey[k] > 0 || s.dials[pr] != nil {
		return nil, ErrDuplicate
	}
	// Dials in progress: those not proved yet, and the reserved places whose hello runs.
	running, places := len(s.dials), len(s.dials)
	for _, o := range s.slots {
		if o.reserved {
			running++
		}
		if o.connect {
			places++
		}
	}
	if s.placesLocked() >= s.cfg.MaxPeers || !s.roomLocked(topic, false) || places >= s.cfg.MaxConnectPeers {
		return nil, errFull
	}
	if h := s.historyLocked(k); h != nil && now.Before(h.next) {
		return nil, ErrWait
	}
	vouched := s.vouchedHistoryLocked(k, pr.addr) != nil
	if backingOff(s.pairFails, pr, now) || !vouched && (backingOff(s.endFails, pr.addr, now) || now.Before(s.hostFloor[host])) {
		return nil, ErrWait
	}
	for _, o := range s.slots {
		if !vouched && o.peer == nil && !o.settled && o.own == host {
			return nil, ErrWait
		}
	}
	for p, d := range s.dials {
		if p.addr.Addr() == host && (!vouched || d.vouched) {
			return nil, ErrWait
		}
	}
	if running >= s.cfg.MaxConnecting || !s.takeConnectLocked(now) {
		return nil, ErrWait
	}
	d := &connectDial{topic: topic, vouched: vouched, cancel: cancel}
	s.dials[pr] = d
	return d, nil
}

// dropDialLocked frees the dial place of pr if it is still d: a later Connect of the same key and address may hold it
// by now. Call with mu held.
func (s *Swarm) dropDialLocked(pr pair, d *connectDial) {
	if s.dials[pr] == d {
		delete(s.dials, pr)
	}
}

// takeConnectLocked takes one Connect dial start from a bucket of MaxConnecting that refills every RetryMin, and
// reports whether there was one. Call with mu held.
func (s *Swarm) takeConnectLocked(now time.Time) bool {
	burst := float64(s.cfg.MaxConnecting)
	if s.connectFill.IsZero() {
		s.connectTokens = burst
	} else {
		s.connectTokens = min(burst, s.connectTokens+burst*float64(now.Sub(s.connectFill))/float64(s.cfg.RetryMin))
	}
	s.connectFill = now
	if s.connectTokens < 1 {
		return false
	}
	s.connectTokens--
	return true
}

// dialDirect dials pub at addr with the swarm's kolo-secure settings, or calls the test hook.
func (s *Swarm) dialDirect(ctx context.Context, addr netip.AddrPort, pub ed25519.PublicKey) (*kolosecure.Conn, error) {
	if s.hooks.dial != nil {
		return s.hooks.dial(ctx, addr, pub)
	}
	return kolosecure.Dial(ctx, addr.String(), s.id, pub, s.cfg.DHT.Secure)
}

// endDial records how a Connect dial that gave no connection ended; Connect frees its place. refund gives its dial
// start back: kolo-secure refused the key before sending anything.
func (s *Swarm) endDial(pr pair, end int, refund bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if refund {
		s.connectTokens = min(float64(s.cfg.MaxConnecting), s.connectTokens+1)
	}
	s.chargeLocked(pr, end, false, releaseFailed, now)
}

// chargeLocked records a failed Connect dial or hello of pr; proved says the key proved itself, and why is the release
// reason then. Every failure the key's own history does not take makes the host wait RetryMin, a wait that does not
// grow, so a peer naming other keys or ports at a live host cannot have it dialed faster than that. Call with mu held.
func (s *Swarm) chargeLocked(pr pair, end int, proved bool, why int, now time.Time) {
	h := s.vouchedHistoryLocked(pr.k, pr.addr)
	switch {
	case end == connectQuiet:
		return
	case end == connectDeadline && h != nil:
		// The caller's deadline never holds off an address lookups found for the key.
		return
	case end == connectProved && h != nil:
		s.releaseBackoffLocked(pr.k, h, why, now)
		return
	case end == connectUnproved:
		failLocked(s, s.endFails, pr.addr, now)
		failLocked(s, s.pairFails, pr, now)
	case end == connectDeadline && !proved:
		failLocked(s, s.endFails, pr.addr, now)
	default:
		// Another key answered, or the key failed after proof at an address no lookup vouched for, such as behind a
		// forwarder a peer named.
		failLocked(s, s.pairFails, pr, now)
	}
	s.hostFloor[pr.addr.Addr()] = now.Add(s.cfg.RetryMin)
	capLocked(s, s.hostFloor, func(t time.Time) time.Time { return t })
}

// releaseConnect frees a slot Connect reserved or took over for topic that no peer holds, stopping the lookup dials
// still running for it, and records how its hello ended; why is the release reason of a failure after the key proved
// itself. A slot taken over keeps the topic of its former place, so the Leave check uses topic.
func (s *Swarm) releaseConnect(k key, sl *slot, topic Topic, addr netip.AddrPort, end, why int) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.slots[k] != sl || sl.peer != nil {
		return
	}
	delete(s.slots, k)
	if sl.inbound {
		s.inbound--
	}
	if sl.dial != nil {
		sl.dial()
	}
	if sl.rdial != nil {
		sl.rdial()
	}
	if end == connectProved && !s.joinedLocked(topic) {
		// Leave ended the hello.
		end = connectQuiet
	}
	s.chargeLocked(pair{k, addr}, end, true, why, now)
	if c := s.cands[k]; c != nil && len(c.topics) == 0 {
		s.dropCandLocked(k)
	}
}

// failLocked grows the backoff of x in m. Call with mu held.
func failLocked[K comparable](s *Swarm, m map[K]*failure, x K, now time.Time) {
	f := m[x]
	if f == nil {
		f = &failure{}
		m[x] = f
	}
	f.fails++
	f.next = now.Add(backoff.Delay(f.fails, s.cfg.RetryMin, s.cfg.RetryMax, nil))
	capLocked(s, m, func(f *failure) time.Time { return f.next })
}

// capLocked lets m grow to twice the candidate budget, then drops the ones whose wait ends soonest, expired ones
// first, down to the budget, so a trim costs O(log n) per entry. Call with mu held.
func capLocked[K comparable, V any](s *Swarm, m map[K]V, end func(V) time.Time) {
	budget := s.budgetLocked()
	if len(m) <= 2*budget {
		return
	}
	type entry struct {
		x    K
		next time.Time
	}
	es := make([]entry, 0, len(m))
	for y, v := range m {
		es = append(es, entry{y, end(v)})
	}
	slices.SortFunc(es, func(a, b entry) int { return a.next.Compare(b.next) })
	for _, e := range es[:len(es)-budget] {
		delete(m, e.x)
	}
}

// backingOff reports whether x is in its backoff in m.
func backingOff[K comparable](m map[K]*failure, x K, now time.Time) bool {
	f := m[x]
	return f != nil && now.Before(f.next)
}

// exhausted reports whether err says the process has no file descriptor left for the dial's own UDP socket, which no
// peer caused: the dial is refused like one past MaxConnectPeers and charges nothing.
func exhausted(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

// connectErr maps a Connect dial that gave no connection to its error; err is the dial's, and canceled reports that
// the dial's context ended.
func (s *Swarm) connectErr(ctx context.Context, topic Topic, err error, canceled bool) error {
	s.mu.Lock()
	left := !s.joinedLocked(topic)
	s.mu.Unlock()
	switch {
	case s.ctx.Err() != nil:
		return ErrClosed
	case ctx.Err() != nil:
		return ctx.Err()
	case exhausted(err):
		return errFull
	case errors.Is(err, kolosecure.ErrInvalidArgument):
		return fmt.Errorf("%w: kolo-secure refused the key or address", ErrInvalidArgument)
	case errors.Is(err, kolosecure.ErrUnexpectedPeer):
		return fmt.Errorf("%w: %w", ErrLost, kolosecure.ErrUnexpectedPeer)
	case canceled && left:
		return errTopicLeft
	}
	return ErrLost
}
