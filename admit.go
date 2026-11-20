package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"time"

	"github.com/ciranda-dev/kolo-swarm/internal/backoff"
	"github.com/ciranda-dev/kolo-swarm/internal/events"
)

// Hello classes (see reserveHello).
const (
	helloStranger = iota
	helloKnown
	helloAttach
)

// ticket is a hello slot taken by reserveHello.
type ticket struct {
	k     key
	src   string
	class int
}

// generation orders the connections an arbiter keeps: a random epoch per Swarm and a counter within it.
type generation struct {
	epoch, n uint64
}

func (s *Swarm) acceptLoop() {
	for {
		c, err := s.node.Accept(s.ctx)
		if err != nil {
			return
		}
		tk, code, ok := s.reserveHello(key(c.RemotePublicKey()), sourceOf(c), true, false)
		if !ok {
			c.CloseWithError(code, "")
			continue
		}
		s.mu.Lock()
		started := s.spawnLocked(func() {
			defer s.releaseHello(tk)
			s.handshake(s.ctx, c, tk.k, true, true)
		})
		s.mu.Unlock()
		if !started {
			s.releaseHello(tk)
			c.CloseWithError(codeNormal, "")
		}
	}
}

// ipv4Only reports whether c has an IPv4 remote address or none.
func ipv4Only(c Conn) bool {
	a := remoteAddr(c)
	return !a.IsValid() || a.Addr().Is4()
}

// sourceOf returns the MaxHandshakesPerIP bucket of c: its IPv4 address, else its relay's key, else one shared bucket.
func sourceOf(c Conn) string {
	if a := remoteAddr(c); a.IsValid() {
		return "ip " + a.Addr().String()
	}
	if r, ok := c.(interface{ RelayPublicKey() ed25519.PublicKey }); ok {
		if rk := r.RelayPublicKey(); len(rk) == ed25519.PublicKeySize {
			return "relay " + string(rk)
		}
	}
	return "none"
}

// reserveHello takes a hello slot for a connection we did not dial, or returns the code to close it with. A quarter
// of MaxHandshakes is kept for Attach and another for known keys.
func (s *Swarm) reserveHello(k key, src string, inbound, attach bool) (ticket, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tk := ticket{k: k, src: src, class: helloStranger}
	switch h := s.historyLocked(k); {
	case attach:
		tk.class = helloAttach
	case (s.slots[k] != nil && !s.slots[k].inbound && !s.slots[k].connect) || (h != nil && h.connected):
		tk.class = helloKnown
	}
	m := s.cfg.MaxHandshakes
	r := m / 4
	notAttach, notKnown := s.hellos-s.attaching, s.strangers+s.attaching
	switch {
	case s.closed:
		return tk, codeNormal, false
	case s.hellos >= m || s.helloKey[k] >= helloPerKey || s.helloSrc[src] >= s.cfg.MaxHandshakesPerIP:
		return tk, codeFull, false
	case tk.class == helloStranger && (s.strangers >= m-2*r || notAttach >= m-r || notKnown >= m-r):
		return tk, codeFull, false
	case tk.class == helloKnown && notAttach >= m-r:
		return tk, codeFull, false
	case tk.class == helloAttach && notKnown >= m-r:
		return tk, codeFull, false
	case s.slots[k] == nil && (s.placesLocked() >= s.cfg.MaxPeers || (inbound && s.inbound >= s.cfg.MaxInbound)):
		return tk, codeFull, false
	}
	s.hellos++
	s.helloKey[k]++
	s.helloSrc[src]++
	switch tk.class {
	case helloStranger:
		s.strangers++
	case helloAttach:
		s.attaching++
	}
	return tk, 0, true
}

func (s *Swarm) releaseHello(tk ticket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hellos--
	switch tk.class {
	case helloStranger:
		s.strangers--
	case helloAttach:
		s.attaching--
	}
	if s.helloSrc[tk.src]--; s.helloSrc[tk.src] <= 0 {
		delete(s.helloSrc, tk.src)
	}
	s.dropHelloKeyLocked(tk.k)
}

// dropHelloKeyLocked ends one hello of k and settles a pending duplicate close once none is left. Call with mu held.
func (s *Swarm) dropHelloKeyLocked(k key) {
	if s.helloKey[k]--; s.helloKey[k] > 0 {
		return
	}
	delete(s.helloKey, k)
	h := s.historyLocked(k)
	if h == nil || !h.dupPending {
		return
	}
	h.dupPending = false
	if sl := s.slots[k]; sl == nil || sl.peer == nil {
		h.fails++
		h.next = time.Now().Add(backoff.Delay(h.fails, s.cfg.RetryMin, s.cfg.RetryMax, nil))
	}
}

// Attach runs the hello on a connection the application opened (outbound if we did) and returns nil once the peer
// is admitted. The connection must authenticate RemotePublicKey itself, as kolo-secure and kolo-relay do: the hello
// carries no proof, so a key the peer merely claims lets it impersonate any key. The swarm owns c from the call on;
// both ends must call it at once (see the README). With Config.Relays, it counts as relayed: a direct connection to
// the key replaces it.
func (s *Swarm) Attach(ctx context.Context, c Conn, outbound bool) error {
	if c == nil {
		return fmt.Errorf("%w: nil Conn", ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		c.CloseWithError(codeNormal, "")
		return err
	}
	pub := c.RemotePublicKey()
	if len(pub) != ed25519.PublicKeySize || bytes.Equal(pub, s.key) {
		c.CloseWithError(codeRefused, "")
		return fmt.Errorf("%w: Conn has no usable remote key", ErrInvalidArgument)
	}
	if !ipv4Only(c) {
		c.CloseWithError(codeRefused, "")
		return errIPv6("remote address")
	}
	tk, code, ok := s.reserveHello(key(pub), sourceOf(c), !outbound, true)
	if !ok {
		c.CloseWithError(code, "")
		if s.ctx.Err() != nil {
			return ErrClosed
		}
		return ErrRefused
	}
	defer s.releaseHello(tk)
	hctx, stop := mergeCtx(ctx, s.ctx)
	defer stop()
	err := s.handshake(hctx, c, tk.k, !outbound, false)
	switch {
	case err == nil:
		return nil
	case s.ctx.Err() != nil:
		return ErrClosed
	case ctx.Err() != nil:
		return ctx.Err()
	}
	return err
}

func (s *Swarm) allow(pub ed25519.PublicKey, addr netip.AddrPort) (ok bool) {
	if s.cfg.Allow == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return s.cfg.Allow(bytes.Clone(pub), addr)
}

// allowGrowth marks c for kolo-transport window growth, once Allow has admitted its peer; with no Allow there is no
// trust decision, and a Conn without the method (a relayed one) never grows.
func (s *Swarm) allowGrowth(c Conn) {
	if g, ok := c.(interface{ AllowWindowGrowth() bool }); ok && s.cfg.Allow != nil {
		if s.hooks.grow != nil {
			s.hooks.grow(c)
		}
		g.AllowWindowGrowth()
	}
}

// admit makes c the connection of k or returns the close code; follow is the non-arbiter, which keeps only a newer
// generation. An attached connection never replaces a direct one.
func (s *Swarm) admit(c Conn, k key, addr netip.AddrPort, inbound, direct bool, topics []Topic, follow bool, gen generation) (*Peer, uint64, error) {
	return s.admitFor(c, k, addr, inbound, direct, topics, follow, gen, nil)
}

// admitFor is admit for a connection Connect dialed into its reservation res, which it enters only while res is still
// the key's place, or for any other when res is nil.
func (s *Swarm) admitFor(c Conn, k key, addr netip.AddrPort, inbound, direct bool, topics []Topic, follow bool, gen generation, res *slot) (*Peer, uint64, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, codeNormal, ErrClosed
	}
	sl := s.slots[k]
	var old *Peer
	switch {
	case res != nil && sl != res:
		s.mu.Unlock()
		return nil, codeDuplicate, ErrDuplicate
	case sl != nil && sl.peer != nil:
		if (!follow && !direct && sl.peer.direct) || (follow && sl.peer.gen.epoch == gen.epoch && sl.peer.gen.n >= gen.n) {
			s.mu.Unlock()
			return nil, codeDuplicate, ErrDuplicate
		}
		old = sl.peer
	case sl == nil && (s.placesLocked() >= s.cfg.MaxPeers || (inbound && s.inbound >= s.cfg.MaxInbound)):
		s.mu.Unlock()
		return nil, codeFull, ErrRefused
	}
	dir := inbound
	if sl != nil {
		dir = sl.inbound
	}
	kept, joined := s.fitLocked(topics, dir, sl)
	if len(kept) == 0 {
		s.mu.Unlock()
		if !joined {
			return nil, codeRefused, ErrRefused
		}
		return nil, codeFull, ErrRefused
	}
	if sl == nil {
		sl = &slot{inbound: inbound}
		s.slots[k] = sl
		if inbound {
			s.inbound++
		}
	}
	// A relayed connection leaves the direct Connect running, so a direct path that works replaces it.
	if sl.dial != nil && (direct || s.relays == nil) {
		sl.dial()
		sl.dial = nil
	}
	if sl.rdial != nil {
		sl.rdial()
		sl.rdial = nil
	}
	if old != nil {
		s.goneLocked(old, ErrDuplicate)
	}
	if !follow {
		gen = s.gen
		s.gen.n++
	}
	if h := s.historyLocked(k); h != nil {
		h.dupPending, h.later = false, 0
	}
	if s.relays != nil {
		s.markRelayedLocked(k, !direct, relayKeyOf(c))
	}
	p := &Peer{s: s, key: bytes.Clone(k[:]), addr: addr, conn: c, direct: direct, inbound: sl.inbound, admitted: time.Now(), topics: kept, gen: gen}
	sl.peer = p
	s.events.Push(Event{Kind: Connected, PublicKey: p.PublicKey(), Addr: addr, Peer: p}, events.Kept)
	s.mu.Unlock()
	context.AfterFunc(c.Context(), func() { s.lost(k, p) })
	// A connection Connect dialed has its own kolo-transport budget, outside MaxGrownMemory, so it never grows.
	if res == nil {
		s.allowGrowth(c)
	}
	if old != nil {
		if s.relays == nil {
			old.conn.CloseWithError(codeDuplicate, "")
		} else {
			s.closeAsync(old.conn, codeDuplicate)
		}
	}
	return p, 0, nil
}

// lost frees the slot of a peer whose connection ended and updates its key's backoff.
func (s *Swarm) lost(k key, p *Peer) {
	err := lostErr(context.Cause(p.conn.Context()))
	now := time.Now()
	s.mu.Lock()
	if p.gone {
		s.mu.Unlock()
		return
	}
	if sl := s.slots[k]; sl != nil && sl.peer == p {
		if sl.reserved {
			// The Connect that reserved the place still runs and keeps it.
			sl.peer = nil
		} else {
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
		}
		if !s.closed && sl.connect {
			// A place Connect took never earns the standing of a key lookups chose.
			// A local close (Leave, Close, the application) is no failure of the key.
			switch h := s.vouchedHistoryLocked(k, p.addr); {
			case err == ErrClosed:
			case h != nil:
				s.lostLocked(k, h, p, err, now, false)
			case err != ErrDuplicate:
				s.chargeLocked(pair{k, p.addr}, connectProved, true, releaseFailed, now)
			}
		} else if c := s.cands[k]; c != nil && !s.closed {
			s.lostLocked(k, &c.history, p, err, now, !p.inbound)
		}
		if c := s.cands[k]; c != nil && !s.closed && len(c.topics) == 0 {
			s.dropCandLocked(k)
		}
	}
	s.goneLocked(p, err)
	s.mu.Unlock()
	s.poke()
}

// lostLocked updates the backoff of k, whose peer p was lost with err; chosen is an outbound place no Connect took.
// Call with mu held.
func (s *Swarm) lostLocked(k key, h *history, p *Peer, err error, now time.Time, chosen bool) {
	if err == ErrDuplicate {
		s.duplicateLocked(k, h, now)
		return
	}
	if now.Sub(p.admitted) >= lasting {
		h.fails = 0
		h.connected = h.connected || chosen
	}
	h.fails++
	h.next = now.Add(backoff.Delay(h.fails, s.cfg.RetryMin, s.cfg.RetryMax, nil))
}

// goneLocked queues the Lost of p, or drops its unread Connected. Call with mu held.
func (s *Swarm) goneLocked(p *Peer, err error) {
	p.gone = true
	if p.delivered {
		s.events.Push(Event{Kind: Lost, PublicKey: p.PublicKey(), Addr: p.addr, Peer: p, Err: err}, events.Kept)
	} else {
		s.events.Remove(func(e Event) bool { return e.Peer == p })
	}
}
