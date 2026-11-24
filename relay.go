package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolorelay "github.com/ciranda-dev/kolo-relay"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	"github.com/ciranda-dev/kolo-swarm/internal/backoff"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// relayLifetime is kolo-relay's close code for a reservation whose ReservationLifetime passed.
const relayLifetime = 2

// relayKeepAlive is kolo-relay's keep-alive on a connection to the relay, which a non-nil Relay replaces.
const relayKeepAlive = 5 * time.Second

// relayState is the swarm's use of one relay. Guarded by Swarm.mu, except the fields set at New.
type relayState struct {
	addr    string
	key     ed25519.PublicKey
	cfg     *kolorelay.Config
	run     *reserveRun // holds the reservation while an announced topic is joined
	held    bool        // a reservation is held now
	off     bool        // the relay key cannot be used: no more use until Close
	down    int         // consecutive relay failures without a status answer; 0 means up
	probeAt time.Time   // while down, when the next relay dial may probe it
	probing bool
}

// reserveRun is one reservation goroutine, from the first announced Join to the last announced Leave.
type reserveRun struct {
	ctx    context.Context
	cancel context.CancelFunc
	first  chan struct{} // closed when the first Reserve attempt returned
	res    map[*kolorelay.Reservation]*heldRes
}

// heldRes counts the open connections a reservation returned; an ended one is forgotten once they are gone.
type heldRes struct {
	conns int
	ended bool
}

func newRelayState(s *Swarm, rl Relay) *relayState {
	// The same kolo-secure and kolo-transport settings as a direct connection; kolorelay sets the listener-only fields.
	sec := *s.cfg.DHT.Secure
	tc := *sec.Transport
	sec.Transport = &tc
	// The outer leg to the relay carries every relayed byte, so it paces and buffers like the swarm's own connections.
	// kolorelay never calls AllowWindowGrowth on it, so WindowGrowth and MaxGrown* stay off.
	leg := &kolosecure.Config{Transport: &kolotransport.Config{
		CongestionControl:      tc.CongestionControl,
		MaxStreamReceiveWindow: tc.MaxStreamReceiveWindow,
		MaxConnReceiveWindow:   tc.MaxConnReceiveWindow,
		KeepAlivePeriod:        relayKeepAlive,
		Datagrams:              s.cfg.RelayDatagrams,
	}}
	return &relayState{
		addr: rl.Addr,
		key:  rl.PublicKey,
		cfg: &kolorelay.Config{
			Peer:      &sec,
			Relay:     leg,
			AllowFunc: func(k ed25519.PublicKey) bool { return s.allow(k, netip.AddrPort{}) },
		},
	}
}

// announcingLocked reports whether a topic joined, or being joined, with Announce is still joined. Call with mu held.
func (s *Swarm) announcingLocked() bool {
	for _, t := range s.topics {
		if t.opts.Announce && !t.left {
			return true
		}
	}
	return false
}

// relayStartLocked starts the reservation goroutine if none runs, and returns what Join waits for: the first Reserve
// attempt, or nil while the relay is known down. Call with mu held.
func (s *Swarm) relayStartLocked(r *relayState) <-chan struct{} {
	if r.off {
		return nil
	}
	if r.run == nil {
		ctx, cancel := context.WithCancel(s.ctx)
		run := &reserveRun{ctx: ctx, cancel: cancel, first: make(chan struct{}), res: map[*kolorelay.Reservation]*heldRes{}}
		if !s.spawnLocked(func() { s.reserveLoop(r, run) }) {
			cancel()
			return nil
		}
		r.run = run
	}
	if r.down > 0 {
		return nil
	}
	return r.run.first
}

// relayStopLocked ends the reservation goroutine once no announced topic is joined. Call with mu held.
func (s *Swarm) relayStopLocked(r *relayState) {
	if r.run == nil || s.announcingLocked() {
		return
	}
	r.run.cancel()
	r.run, r.held = nil, false
	s.relayChangedLocked(r, ErrClosed)
}

// relayChangedLocked queues RelayChanged for r, replacing the one queued for r. Call with mu held.
func (s *Swarm) relayChangedLocked(r *relayState, err error) {
	s.events.Remove(func(e Event) bool { return e.Kind == RelayChanged && bytes.Equal(e.PublicKey, r.key) })
	s.events.Push(Event{Kind: RelayChanged, PublicKey: bytes.Clone(r.key), Err: err}, classRelay)
}

// relayOffLocked stops every use of the relay after its key was refused. Call with mu held.
func (s *Swarm) relayOffLocked(r *relayState) {
	if r.off {
		return
	}
	r.off = true
	if r.run != nil {
		r.run.cancel()
		r.run, r.held = nil, false
	}
	s.relayChangedLocked(r, ErrInvalidConfig)
}

// relayErr maps a Reserve or Dial error to the sentinel RelayChanged carries, so it holds nothing the relay sent.
func relayErr(err error) error {
	for _, e := range []error{kolorelay.ErrNotAllowed, kolorelay.ErrLimit, kolorelay.ErrReservationEnded, kolosecure.ErrUnexpectedPeer} {
		if errors.Is(err, e) {
			return e
		}
	}
	if errors.Is(err, kolosecure.ErrInvalidArgument) || errors.Is(err, kolorelay.ErrInvalidArgument) || errors.Is(err, kolorelay.ErrInvalidConfig) {
		return ErrInvalidConfig
	}
	return ErrLost
}

// relayHealthLocked marks the relay up after a success or a status answer, and down after any other failure, unless
// a reservation is held. Call with mu held.
func (s *Swarm) relayHealthLocked(r *relayState, err error) {
	switch {
	case err == nil, errors.Is(err, kolorelay.ErrUnavailable), errors.Is(err, kolorelay.ErrLimit), errors.Is(err, kolorelay.ErrNotAllowed):
		r.down = 0
	case !r.held:
		r.down++
		r.probeAt = time.Now().Add(backoff.Delay(r.down, s.cfg.RetryMin, s.cfg.RetryMax, nil))
	}
}

// relayTarget returns the relay's address: the literal, or the first usable IPv4 address its name resolves to.
func (s *Swarm) relayTarget(ctx context.Context, r *relayState) (string, error) {
	addr := r.addr
	host, _, _ := net.SplitHostPort(addr)
	if _, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	addrs, err := resolveNodes(ctx, []string{addr}, s.localIP())
	if err != nil {
		return "", err
	}
	return addrs[0].String(), nil
}

// wait sleeps for d and reports whether ctx is still alive.
func wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// reserveLoop keeps a reservation at the relay until run ends, and admits the peers that come through it.
func (s *Swarm) reserveLoop(r *relayState, run *reserveRun) {
	defer s.closeRun(r, run)
	first := run.first
	defer func() {
		if first != nil {
			close(first)
		}
	}()
	fails := 0
	for run.ctx.Err() == nil {
		res, err := s.reserve(run.ctx, r)
		if first != nil {
			close(first)
			first = nil
		}
		if run.ctx.Err() != nil {
			if err == nil {
				res.Close()
			}
			return
		}
		if err != nil {
			e := relayErr(err)
			s.mu.Lock()
			s.relayHealthLocked(r, err)
			if e == ErrInvalidConfig {
				s.relayOffLocked(r)
			} else if r.run == run {
				s.relayChangedLocked(r, e)
			}
			s.mu.Unlock()
			fails++
			if e == ErrInvalidConfig || !wait(run.ctx, backoff.Delay(fails, s.cfg.RetryMin, s.cfg.RetryMax, nil)) {
				return
			}
			continue
		}
		held := time.Now()
		s.mu.Lock()
		run.res[res] = &heldRes{}
		if r.run == run {
			r.held = true
			s.relayHealthLocked(r, nil)
			s.relayChangedLocked(r, nil)
		}
		s.mu.Unlock()
		end := s.serveReservation(run, res)
		if run.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		if h := run.res[res]; h != nil {
			h.ended = true
			if h.conns == 0 {
				delete(run.res, res)
			}
		}
		if r.run == run {
			r.held = false
			s.relayChangedLocked(r, kolorelay.ErrReservationEnded)
		}
		s.mu.Unlock()
		var delay time.Duration
		fails, delay = s.reserveRetry(fails, time.Since(held), end)
		if !wait(run.ctx, delay) {
			return
		}
	}
}

// reserveRetry returns the failure count and the wait before the next Reserve after a reservation held for d ended
// with end: one that lasted resets the count, and a lifetime end is not a failure.
func (s *Swarm) reserveRetry(fails int, d time.Duration, end error) (int, time.Duration) {
	if d >= lasting {
		fails = 0
	}
	if lifetimeEnd(end) {
		return fails, s.cfg.RetryMin
	}
	fails++
	return fails, backoff.Delay(fails, s.cfg.RetryMin, s.cfg.RetryMax, nil)
}

// lifetimeEnd reports whether a reservation ended because its ReservationLifetime passed, which is not a failure.
func lifetimeEnd(err error) bool {
	var te *kolotransport.Error
	return errors.As(err, &te) && errors.Is(te.Err, kolotransport.ErrStreamReset) && te.Code == relayLifetime
}

func (s *Swarm) reserve(ctx context.Context, r *relayState) (*kolorelay.Reservation, error) {
	addr, err := s.relayTarget(ctx, r)
	if err != nil {
		return nil, err
	}
	return kolorelay.Reserve(ctx, addr, r.key, s.id, r.cfg)
}

// serveReservation admits the connections res returns until it ends, then those still ready, and returns its end
// error, or nil once run ends. An ended reservation is never closed here: kolorelay closes its relay connection once
// its last connection ends, and Close would end the relayed peers.
func (s *Swarm) serveReservation(run *reserveRun, res *kolorelay.Reservation) error {
	var end error
	for {
		c, err := s.acceptRelayed(run.ctx, res)
		switch {
		case err == nil:
			s.adoptRelayed(run, res, c)
			continue
		case run.ctx.Err() != nil:
			return nil
		case end != nil:
			return end
		}
		end = err
	}
}

func (s *Swarm) acceptRelayed(ctx context.Context, res *kolorelay.Reservation) (Conn, error) {
	if s.hooks.accept != nil {
		return s.hooks.accept(ctx, res)
	}
	c, err := res.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// adoptRelayed runs the hello on a connection the reservation accepted, as acceptLoop does for kolo-dht's.
func (s *Swarm) adoptRelayed(run *reserveRun, res *kolorelay.Reservation, c Conn) {
	s.mu.Lock()
	if h := run.res[res]; h != nil {
		h.conns++
		context.AfterFunc(c.Context(), func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if h.conns--; h.ended && h.conns == 0 && run.res[res] == h {
				delete(run.res, res)
			}
		})
	}
	s.mu.Unlock()
	pub := c.RemotePublicKey()
	if len(pub) != ed25519.PublicKeySize || bytes.Equal(pub, s.key) {
		s.closeAsync(c, codeRefused)
		return
	}
	tk, code, ok := s.reserveHello(key(pub), sourceOf(c), true, false)
	if !ok {
		s.closeAsync(c, code)
		return
	}
	s.mu.Lock()
	started := s.spawnLocked(func() {
		defer s.releaseHello(tk)
		s.handshake(s.ctx, c, tk.k, true, false)
	})
	s.mu.Unlock()
	if !started {
		s.releaseHello(tk)
		c.CloseWithError(codeNormal, "")
	}
}

// closeRun closes every reservation of run, in parallel since each close can take seconds.
func (s *Swarm) closeRun(r *relayState, run *reserveRun) {
	s.mu.Lock()
	var all []*kolorelay.Reservation
	for res := range run.res {
		all = append(all, res)
	}
	run.res = map[*kolorelay.Reservation]*heldRes{}
	if r.run == run {
		r.run, r.held = nil, false
	}
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, res := range all {
		wg.Go(func() { res.Close() })
	}
	wg.Wait()
}

// relayKeyOf returns the key of the relay a connection goes through, or nil.
func relayKeyOf(c Conn) ed25519.PublicKey {
	if r, ok := c.(interface{ RelayPublicKey() ed25519.PublicKey }); ok {
		return r.RelayPublicKey()
	}
	return nil
}

// markRelayedLocked sets or clears k's relayed flag and, for a connection through a listed relay, its last relay,
// keeping them in past if k is no candidate. Call with mu held.
func (s *Swarm) markRelayedLocked(k key, relayed bool, via ed25519.PublicKey) {
	h := s.historyLocked(k)
	if h == nil {
		if !relayed {
			return
		}
		s.rememberLocked(k, history{relayed: true})
		if h = s.historyLocked(k); h == nil {
			return
		}
	}
	h.relayed = relayed
	if s.relayByKeyLocked(via) != nil {
		h.lastRelay = key(via)
	}
}

// relayByKeyLocked returns the listed relay whose key is k, or nil. Call with mu held.
func (s *Swarm) relayByKeyLocked(k ed25519.PublicKey) *relayState {
	for _, r := range s.relays {
		if bytes.Equal(r.key, k) {
			return r
		}
	}
	return nil
}

// nextRelayLocked returns the next relay of a chain to target: the one that last carried k, then list order,
// skipping those tried, stopped, or down unless a probe is due; probe reports a probe. Call with mu held.
func (s *Swarm) nextRelayLocked(k key, target ed25519.PublicKey, tried map[*relayState]bool) (r *relayState, probe bool) {
	order := s.relays
	if h := s.historyLocked(k); h != nil && h.lastRelay != (key{}) {
		if last := s.relayByKeyLocked(h.lastRelay[:]); last != nil {
			order = append([]*relayState{last}, s.relays...)
		}
	}
	now := time.Now()
	for _, r := range order {
		switch {
		case tried[r] || r.off || bytes.Equal(r.key, target):
		case r.down == 0:
			return r, false
		case !r.probing && !now.Before(r.probeAt):
			r.probing = true
			return r, true
		}
	}
	return nil, false
}

// punchProbes is kolo-dht's probe schedule of two consistent mappings: 10 probes 1s apart.
const punchProbes = 10 * time.Second

// relayAfterLocked is how long a first-contact Connect runs alone before the relays are tried too: kolo-dht's punch
// window of two consistent mappings, its probes plus twice RequestTimeout (default 1s). Call with mu held.
func (s *Swarm) relayAfterLocked() time.Duration {
	if s.hooks.relayAfter > 0 {
		return s.hooks.relayAfter
	}
	rt := s.cfg.DHT.RequestTimeout
	if rt == 0 {
		rt = time.Second
	}
	return punchProbes + 2*rt
}

// dialVia is dial with Config.Relays: a key whose flag is set is dialed directly and through the relays at once;
// another is dialed through the relays once its direct Connect failed or outlasted the punch window.
func (s *Swarm) dialVia(ctx context.Context, cancel context.CancelFunc, k key, sl *slot, rec kolodht.Record, topic Topic) {
	defer func() {
		cancel()
		s.mu.Lock()
		s.dialing--
		s.mu.Unlock()
		s.poke()
	}()
	if !s.allow(rec.PublicKey, rec.Addr) {
		s.release(k, sl, releaseDenied)
		return
	}
	s.mu.Lock()
	sl.paths = 1
	if h := s.historyLocked(k); h != nil && h.relayed {
		s.startChainLocked(k, sl, rec, topic)
	}
	// Past the window only a random mapping can still connect, which may take PunchTimeout per storer.
	returned := false
	late := time.AfterFunc(s.relayAfterLocked(), func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !returned && ctx.Err() == nil && s.slots[k] == sl && sl.peer == nil {
			s.startChainLocked(k, sl, rec, topic)
		}
	})
	s.mu.Unlock()
	c, err := s.connectNode(ctx, rec)
	s.mu.Lock()
	returned = true
	s.mu.Unlock()
	late.Stop()
	if err != nil {
		why := releaseQuiet
		if ctx.Err() == nil {
			why = connectRelease(err)
		}
		s.mu.Lock()
		sl.settled = true
		if why == releaseFailed {
			s.markRelayedLocked(k, true, nil)
			if !sl.relaying && s.ctx.Err() == nil {
				s.startChainLocked(k, sl, rec, topic)
			}
			if sl.relaying {
				sl.unreach = errors.Is(err, kolodht.ErrUnreachable)
			} else {
				// No relay dial was free: the relays were not tried, so the key comes back as after try later.
				why = releaseLater
			}
		}
		s.mu.Unlock()
		s.endPath(k, sl, rec, topic, why)
		return
	}
	s.mu.Lock()
	taken := (sl.peer != nil && sl.peer.direct) || s.slots[k] != sl || s.closed || s.helloKey[k] >= helloPerKey
	if !taken {
		s.helloKey[k]++
	}
	s.mu.Unlock()
	if taken {
		c.CloseWithError(codeDuplicate, "")
		s.endPath(k, sl, rec, topic, releaseQuiet)
		return
	}
	err = s.handshake(s.ctx, c, k, false, true)
	s.mu.Lock()
	s.dropHelloKeyLocked(k)
	s.mu.Unlock()
	s.endPath(k, sl, rec, topic, helloRelease(err))
}

// helloRelease says how release treats a key after its dialed connection's hello returned err.
func helloRelease(err error) int {
	switch {
	case err == nil:
		return releaseQuiet
	case errors.Is(err, ErrDuplicate):
		return releaseDuplicate
	}
	return releaseFailed
}

// startChainLocked starts the slot's one relay chain if a relay dial is free. A chain holds one of the MaxConnecting
// relay dials, since it dials one relay at a time. Call with mu held.
func (s *Swarm) startChainLocked(k key, sl *slot, rec kolodht.Record, topic Topic) {
	if sl.relaying || s.closed || s.relayed >= s.cfg.MaxConnecting {
		return
	}
	rctx, rcancel := context.WithCancel(s.ctx)
	if !s.spawnLocked(func() { s.relayChain(rctx, rcancel, k, sl, rec, topic) }) {
		rcancel()
		return
	}
	s.relayed++
	sl.relaying, sl.rdial = true, rcancel
	sl.paths++
}

// relayChain dials k through its relays one at a time until one gives a connection, and runs the hello on it.
func (s *Swarm) relayChain(ctx context.Context, cancel context.CancelFunc, k key, sl *slot, rec kolodht.Record, topic Topic) {
	defer cancel()
	var rc *kolorelay.Conn
	tried := map[*relayState]bool{}
	for ctx.Err() == nil {
		s.mu.Lock()
		r, probe := s.nextRelayLocked(k, rec.PublicKey, tried)
		s.mu.Unlock()
		if r == nil {
			break
		}
		tried[r] = true
		if s.hooks.beforeRelay != nil {
			s.hooks.beforeRelay(ctx, bytes.Clone(r.key), bytes.Clone(k[:]))
		}
		addr, err := s.relayTarget(ctx, r)
		if err == nil {
			rc, err = kolorelay.Dial(ctx, addr, r.key, s.id, rec.PublicKey, r.cfg)
		}
		s.mu.Lock()
		if probe {
			r.probing = false
		}
		if ctx.Err() == nil {
			s.relayHealthLocked(r, err)
			if err != nil && relayErr(err) == ErrInvalidConfig {
				s.relayOffLocked(r)
			}
		}
		s.mu.Unlock()
		if err == nil {
			break
		}
	}
	s.mu.Lock()
	s.relayed--
	s.mu.Unlock()
	s.poke()
	if rc == nil {
		why := releaseFailed
		if ctx.Err() != nil {
			why = releaseQuiet
		}
		s.endPath(k, sl, rec, topic, why)
		return
	}
	s.mu.Lock()
	taken := sl.peer != nil || s.slots[k] != sl || s.closed || s.helloKey[k] >= helloPerKey
	if !taken {
		s.helloKey[k]++
	}
	s.mu.Unlock()
	if taken {
		s.closeAsync(rc, codeDuplicate)
		s.endPath(k, sl, rec, topic, releaseQuiet)
		return
	}
	err := s.handshake(s.ctx, rc, k, false, false)
	s.mu.Lock()
	s.dropHelloKeyLocked(k)
	s.mu.Unlock()
	s.endPath(k, sl, rec, topic, helloRelease(err))
}

// releaseRank orders release reasons; the slot is released with the worst of its paths'.
var releaseRank = map[int]int{releaseQuiet: 0, releaseLater: 1, releaseDenied: 2, releaseFailed: 3, releaseDuplicate: 4}

// endPath ends one dial path of sl and, once every path ended, releases the slot and queues Unreachable if the
// direct Connect returned kolodht.ErrUnreachable and no path connected.
func (s *Swarm) endPath(k key, sl *slot, rec kolodht.Record, topic Topic, why int) {
	s.mu.Lock()
	if releaseRank[why] > releaseRank[sl.why] {
		sl.why = why
	}
	sl.paths--
	last := sl.paths == 0
	unreach := last && sl.unreach && s.slots[k] == sl && sl.peer == nil
	why = sl.why
	s.mu.Unlock()
	if !last {
		return
	}
	if unreach && why == releaseFailed && s.rotate(k, topic, rec) {
		why = releaseQuiet
	}
	s.release(k, sl, why)
	if unreach {
		s.unreachable(topic, rec)
	}
}
