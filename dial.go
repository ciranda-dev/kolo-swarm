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

// dialTopicLocked returns the joined topic of c to dial for: one with room and a record not suspect, the one holding
// the fewest places for its fair share. Call with mu held.
func (s *Swarm) dialTopicLocked(c *cand, ta tally, j int) (Topic, bool) {
	var best Topic
	found := false
	for x := range c.topics {
		if t := s.topics[x]; t == nil || t.joining || !s.roomIn(ta, x, false) {
			continue
		}
		if !found || s.dialBefore(c, ta, j, x, best) {
			best, found = x, true
		}
	}
	return best, found
}

// dialBefore reports whether a dial for topic a is preferred to one for b: a record not suspect first, then the lower
// share of its fair share held.
func (s *Swarm) dialBefore(c *cand, ta tally, j int, a, b Topic) bool {
	if c.suspect[a] != c.suspect[b] {
		return c.suspect[b]
	}
	return int64(ta[a].total)*int64(s.shareOf(s.topics[b], j)) < int64(ta[b].total)*int64(s.shareOf(s.topics[a], j))
}

// needOf ranks the need of topic x for a dial: 0 below its outbound minimum, 1 below its fair share, else 2.
func (s *Swarm) needOf(ta tally, x Topic, j int) int {
	t := s.topics[x]
	switch n := ta[x]; {
	case n.out < s.minOutOf(t, j):
		return 0
	case n.total < s.shareOf(t, j):
		return 1
	}
	return 2
}

// dialSome starts the dials that limits and backoff allow and returns how long until the next may start.
func (s *Swarm) dialSome() time.Duration {
	s.mu.Lock()
	wait, evicted := s.dialRoundLocked(time.Now())
	s.mu.Unlock()
	for _, c := range evicted {
		s.closeAsync(c, codeFull)
	}
	return wait
}

// dialRoundLocked is dialSome under mu; it also returns the connections it evicted, to close after the unlock.
func (s *Swarm) dialRoundLocked(now time.Time) (time.Duration, []Conn) {
	wait := time.Minute
	if s.closed {
		return wait, nil
	}
	ta, j := s.tallyLocked(), s.joinedCountLocked()
	full := s.placesLocked() >= s.cfg.MaxPeers
	type choice struct {
		k    key
		c    *cand
		need int
	}
	var ready []choice
	for k, c := range s.cands {
		if s.slots[k] != nil || s.helloKey[k] > 0 {
			continue
		}
		x, ok := s.dialTopicLocked(c, ta, j)
		if !ok {
			continue
		}
		if now.Before(c.next) {
			wait = min(wait, c.next.Sub(now))
			continue
		}
		need := s.needOf(ta, x, j)
		if full && need == 2 {
			continue
		}
		ready = append(ready, choice{k, c, need})
	}
	// Topics below their outbound minimum, then below their fair share, first; then keys whose outbound connection
	// lasted, then fewest failures; a TryLater weighs as a failure here.
	rand.Shuffle(len(ready), func(i, j int) { ready[i], ready[j] = ready[j], ready[i] })
	slices.SortStableFunc(ready, func(a, b choice) int {
		if a.need != b.need {
			return a.need - b.need
		}
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
	var evicted []Conn
	noVictim := map[Topic]bool{}
	for _, ch := range ready {
		if s.dialing >= s.cfg.MaxConnecting {
			break
		}
		topic, ok := s.dialTopicLocked(ch.c, ta, j)
		if !ok {
			continue
		}
		rec := ch.c.recOf(topic)
		own, via := s.hostsLocked(rec)
		if ownBusy[own] || slices.ContainsFunc(via, func(h netip.Addr) bool { return anyBusy[h] }) {
			continue
		}
		if s.placesLocked() >= s.cfg.MaxPeers {
			if s.needOf(ta, topic, j) == 2 || noVictim[topic] {
				continue
			}
			victim := s.evictForLocked(topic, ta, j)
			if victim == nil {
				noVictim[topic] = true
				continue
			}
			evicted = append(evicted, victim)
		}
		mark(own, via)
		dctx, cancel := context.WithCancel(s.ctx)
		sl := &slot{topic: topic, own: own, via: via, dial: cancel}
		s.slots[ch.k] = sl
		n := ta[topic]
		n.total++
		n.out++
		ta[topic] = n
		s.dialing++
		k := ch.k
		if s.relays != nil {
			s.spawnLocked(func() { s.dialVia(dctx, cancel, k, sl, rec, topic) })
		} else {
			s.spawnLocked(func() { s.dial(dctx, cancel, k, sl, rec, topic) })
		}
	}
	return max(wait, minWait), evicted
}

// evictForLocked frees one place for a dial of topic x, which is under its outbound minimum or its fair share, and
// returns the connection to close; nil if no peer can go. The victim is a peer that no hello holds and no Connect
// still runs for, whose every topic keeps its fair share (and its outbound minimum, for an outbound peer of our
// lookups) without it. Inbound peers go first, then Connect places, then outbound peers, the newest of a class first,
// so long-lived outbound peers stay. An inbound peer of x itself may go when x lacks outbound peers: its place turns
// outbound. The slot goes at once, so the victim's key is charged nothing. Call with mu held.
func (s *Swarm) evictForLocked(x Topic, ta tally, j int) Conn {
	lowOut := ta[x].out < s.minOutOf(s.topics[x], j)
	var vk key
	var vs *slot
	rank := func(sl *slot) int {
		switch {
		case sl.inbound:
			return 0
		case sl.connect:
			return 1
		}
		return 2
	}
	for k, sl := range s.slots {
		p := sl.peer
		if p == nil || p.gone || sl.reserved || s.helloKey[k] > 0 {
			continue
		}
		out := !sl.inbound && !sl.connect
		keeps := true
		for _, y := range p.topics {
			n, ty := ta[y], s.topics[y]
			if y == x && sl.inbound && lowOut {
				continue
			}
			if n.total-1 < s.shareOf(ty, j) || out && n.out-1 < s.minOutOf(ty, j) {
				keeps = false
				break
			}
		}
		if !keeps {
			continue
		}
		if vs == nil || rank(sl) < rank(vs) || rank(sl) == rank(vs) && sl.peer.admitted.After(vs.peer.admitted) {
			vk, vs = k, sl
		}
	}
	if vs == nil {
		return nil
	}
	delete(s.slots, vk)
	if vs.inbound {
		s.inbound--
	}
	if vs.dial != nil {
		vs.dial()
	}
	if vs.rdial != nil {
		vs.rdial()
	}
	out := !vs.inbound && !vs.connect
	for _, y := range vs.peer.topics {
		n := ta[y]
		n.total--
		if vs.inbound {
			n.inbound--
		}
		if out {
			n.out--
		}
		ta[y] = n
	}
	return vs.peer.conn
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
		why, unreach := connectRelease(err), errors.Is(err, kolodht.ErrUnreachable)
		if unreach && why == releaseFailed && s.rotate(k, topic, rec) {
			why = releaseQuiet
		}
		s.release(k, sl, why)
		if unreach {
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

// rotate marks k's record for topic suspect after kolodht.ErrUnreachable and reports whether k has a record of
// another topic not suspect to dial next; if not, the round of records is over and they all count again. Only the
// dial that ends a round is a failure of the key.
func (s *Swarm) rotate(k key, topic Topic, rec kolodht.Record) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cands[k]
	if c == nil || !c.topics[topic] {
		return false
	}
	if c.recOf(topic).Addr == rec.Addr {
		if c.suspect == nil {
			c.suspect = make(map[Topic]bool)
		}
		c.suspect[topic] = true
	}
	for x := range c.topics {
		if x != topic && !c.suspect[x] && s.joinedLocked(x) {
			return true
		}
	}
	clear(c.suspect)
	return false
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
