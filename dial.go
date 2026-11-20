package koloswarm

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	"github.com/ciranda-dev/kolo-swarm/internal/backoff"
)

func (s *Swarm) dialLoop() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		timer.Reset(s.dialSome())
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		case <-timer.C:
		}
	}
}

// dialTopicLocked returns a joined topic of c with room. Call with mu held.
func (s *Swarm) dialTopicLocked(c *cand) (Topic, bool) {
	for x := range c.topics {
		if t := s.topics[x]; t != nil && !t.joining && s.roomLocked(x, false) {
			return x, true
		}
	}
	return Topic{}, false
}

// dialSome starts the dials that limits and backoff allow and returns how long until the next may start.
func (s *Swarm) dialSome() time.Duration {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	wait := time.Minute
	if s.closed {
		return wait
	}
	type choice struct {
		k key
		c *cand
	}
	var ready []choice
	for k, c := range s.cands {
		if s.slots[k] != nil || s.helloKey[k] > 0 {
			continue
		}
		if _, ok := s.dialTopicLocked(c); !ok {
			continue
		}
		if now.Before(c.next) {
			wait = min(wait, c.next.Sub(now))
			continue
		}
		ready = append(ready, choice{k, c})
	}
	// Keys whose outbound connection lasted first, then fewest failures; a TryLater weighs as a failure here.
	rand.Shuffle(len(ready), func(i, j int) { ready[i], ready[j] = ready[j], ready[i] })
	slices.SortStableFunc(ready, func(a, b choice) int {
		if a.c.connected != b.c.connected {
			if a.c.connected {
				return -1
			}
			return 1
		}
		return a.c.fails + a.c.later - b.c.fails - b.c.later
	})
	// kolo-dht opens 2 sessions per host, and a server can forge records there. A host takes one dial at its own
	// Addr and one through a relay, so forged relay addresses cannot hold off the key that lives there.
	ownBusy, anyBusy := map[netip.Addr]bool{}, map[netip.Addr]bool{}
	mark := func(own netip.Addr, via []netip.Addr) {
		ownBusy[own], anyBusy[own] = true, true
		for _, h := range via {
			anyBusy[h] = true
		}
	}
	// A Connect dial has its own socket and takes no kolo-dht session, so it does not hold its host.
	for _, sl := range s.slots {
		if sl.peer == nil && !sl.settled && !sl.connect {
			mark(sl.own, sl.via)
		}
	}
	for _, ch := range ready {
		if s.dialing >= s.cfg.MaxConnecting || s.placesLocked() >= s.cfg.MaxPeers {
			break
		}
		topic, ok := s.dialTopicLocked(ch.c)
		own, via := s.hostsLocked(ch.c.rec)
		if !ok || ownBusy[own] || slices.ContainsFunc(via, func(h netip.Addr) bool { return anyBusy[h] }) {
			continue
		}
		mark(own, via)
		dctx, cancel := context.WithCancel(s.ctx)
		sl := &slot{topic: topic, own: own, via: via, dial: cancel}
		s.slots[ch.k] = sl
		s.dialing++
		rec, k := ch.c.rec, ch.k
		if s.relays != nil {
			s.spawnLocked(func() { s.dialVia(dctx, cancel, k, sl, rec, topic) })
		} else {
			s.spawnLocked(func() { s.dial(dctx, cancel, k, sl, rec, topic) })
		}
	}
	return max(wait, minWait)
}

// hostsLocked returns the IPv4 host of rec.Addr and the other hosts kolo-dht may probe or dial for rec. Call with mu
// held.
func (s *Swarm) hostsLocked(rec kolodht.Record) (own netip.Addr, via []netip.Addr) {
	addrs := rec.Addrs()
	if s.hooks.addrsOf != nil {
		addrs = s.hooks.addrsOf(rec)
	}
	own = rec.Addr.Addr()
	for _, a := range addrs {
		if a.Addr() != own {
			via = append(via, a.Addr())
		}
	}
	return own, via
}

const (
	releaseQuiet = iota
	releaseFailed
	releaseDenied
	releaseDuplicate
	releaseLater
)

func (s *Swarm) dial(ctx context.Context, cancel context.CancelFunc, k key, sl *slot, rec kolodht.Record, topic Topic) {
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
	c, err := s.connectNode(ctx, rec)
	if err != nil {
		if ctx.Err() != nil {
			s.release(k, sl, releaseQuiet)
			return
		}
		s.release(k, sl, connectRelease(err))
		if errors.Is(err, kolodht.ErrUnreachable) {
			s.unreachable(topic, rec)
		}
		return
	}
	s.mu.Lock()
	taken := sl.peer != nil || s.slots[k] != sl || s.closed || s.helloKey[k] >= helloPerKey
	if !taken {
		s.helloKey[k]++
	}
	s.mu.Unlock()
	if taken {
		c.CloseWithError(codeDuplicate, "")
		s.release(k, sl, releaseQuiet)
		return
	}
	err = s.handshake(s.ctx, c, k, false, true)
	s.mu.Lock()
	s.dropHelloKeyLocked(k)
	s.mu.Unlock()
	if err != nil {
		s.release(k, sl, helloRelease(err))
	}
}

// connectNode calls kolo-dht Connect, or the test hook.
func (s *Swarm) connectNode(ctx context.Context, rec kolodht.Record) (*kolosecure.Conn, error) {
	if s.hooks.connect != nil {
		return s.hooks.connect(ctx, rec)
	}
	return s.node.Connect(ctx, rec)
}

// connectRelease says how release treats a key whose Connect failed with err. ErrTryLater (a punch budget here or at
// the peer, a relay's answer, or kolo-dht busy toward the host) is not counted as a failure, but its wait grows.
func connectRelease(err error) int {
	switch {
	case errors.Is(err, kolodht.ErrInvalidArgument):
		return releaseDenied
	case errors.Is(err, kolodht.ErrTryLater):
		return releaseLater
	}
	return releaseFailed
}

func (s *Swarm) unreachable(topic Topic, rec kolodht.Record) {
	s.events.Push(Event{Kind: Unreachable, Topic: topic, PublicKey: bytes.Clone(rec.PublicKey), Addr: rec.Addr, Err: kolodht.ErrUnreachable}, classUnreachable)
}

// release frees a dial's slot if no peer took it and updates its key's backoff.
func (s *Swarm) release(k key, sl *slot, why int) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.slots[k] != sl || sl.peer != nil || sl.reserved {
		// A reserved slot is the running Connect's to release.
		return
	}
	delete(s.slots, k)
	c := s.cands[k]
	if c == nil || s.closed {
		return
	}
	s.releaseBackoffLocked(k, &c.history, why, now)
	if len(c.topics) == 0 {
		s.dropCandLocked(k)
	}
}

// releaseBackoffLocked updates the backoff of k, whose dial ended for why. Call with mu held.
func (s *Swarm) releaseBackoffLocked(k key, h *history, why int, now time.Time) {
	switch why {
	case releaseFailed:
		h.fails++
		h.next = now.Add(backoff.Delay(h.fails, s.cfg.RetryMin, s.cfg.RetryMax, nil))
	case releaseDuplicate:
		s.duplicateLocked(k, h, now)
	case releaseDenied:
		h.next = now.Add(s.cfg.LookupInterval)
	case releaseLater:
		h.later++
		h.next = now.Add(s.laterDelay(h.later))
	}
}

// laterDelay is the wait after n ErrTryLater since the key's last admission. It starts at kolo-dht's RandomPunchInterval, the least time
// between two random punches, so a node behind a random NAT does not redial every candidate each second.
func (s *Swarm) laterDelay(n int) time.Duration {
	first := s.cfg.DHT.RandomPunchInterval
	if first == 0 {
		first = kolodht.DefaultRandomPunchInterval
	}
	return backoff.Delay(n, first, max(first, s.cfg.RetryMax), nil)
}

// duplicateLocked delays a key closed as a duplicate. It is a failure unless another connection to it is admitted;
// with a hello in progress, that is decided when the hello ends. Call with mu held.
func (s *Swarm) duplicateLocked(k key, h *history, now time.Time) {
	switch {
	case s.slots[k] != nil && s.slots[k].peer != nil:
	case s.helloKey[k] > 0:
		h.dupPending = true
	default:
		h.fails++
	}
	h.next = now.Add(backoff.Delay(max(h.fails, 1), s.cfg.RetryMin, s.cfg.RetryMax, nil))
}
