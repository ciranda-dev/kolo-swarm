package koloswarm

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	"github.com/ciranda-dev/kolo-swarm/internal/hello"
)

// history is the state of a key kept across lookups.
type history struct {
	fails      int
	next       time.Time
	addr       netip.AddrPort // the address of its latest record
	later      int            // ErrTryLater results, and failed Connects with no relay dial free, since its last admission
	connected  bool           // an outbound connection to it lasted at least 15s
	dupPending bool           // closed as a duplicate while another connection to it was in its hello
	relayed    bool           // with Config.Relays: its last admitted connection was relayed, or its last Connect failed
	lastRelay  key            // with Config.Relays: the relay of its last admitted relayed connection
}

// cand is a key returned by lookups.
type cand struct {
	rec     kolodht.Record // the latest record any lookup returned
	recs    map[Topic]kolodht.Record
	suspect map[Topic]bool // topics whose record failed with ErrUnreachable and no lookup returned it again since
	topics  map[Topic]bool
	history
}

// recOf is the record of c that a lookup of x returned.
func (c *cand) recOf(x Topic) kolodht.Record {
	if r, ok := c.recs[x]; ok {
		return r
	}
	return c.rec
}

// lookupDelay is interval plus up to a fifth of it, for a random r in [0, 1).
func lookupDelay(interval time.Duration, r float64) time.Duration {
	return interval + time.Duration(float64(interval/5)*r)
}

func (s *Swarm) lookupLoop(topic Topic, t *topicState) {
	for {
		s.mu.Lock()
		n, _ := s.countsLocked(topic)
		full := n >= s.capOf(t)
		s.mu.Unlock()
		if !full {
			if recs, err := s.node.Lookup(t.ctx, topic); err == nil {
				s.found(topic, t, recs)
			}
			if s.hooks.afterLookup != nil {
				s.hooks.afterLookup()
			}
		}
		timer := time.NewTimer(lookupDelay(s.cfg.LookupInterval, rand.Float64()))
		select {
		case <-t.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// found makes the records of one lookup the candidates of topic, within its share. Half the share is kept for known
// keys; the rest is a uniform sample, so record order, age and claimed address never count.
func (s *Swarm) found(topic Topic, t *topicState, recs []kolodht.Record) {
	s.mu.Lock()
	if s.topics[topic] != t || t.left {
		s.mu.Unlock()
		return
	}
	quota := s.quotaLocked()
	prev := map[key]*cand{}
	for k, c := range s.cands {
		if c.topics[topic] {
			prev[k] = c
		}
	}
	var known, rest []kolodht.Record
	rank := map[key]int{}
	for _, r := range recs {
		if len(r.PublicKey) != ed25519.PublicKeySize || !r.Addr.Addr().Is4() {
			continue
		}
		k := key(r.PublicKey)
		if _, dup := rank[k]; dup || k == s.self {
			continue
		}
		rank[k] = s.standingLocked(k)
		if rank[k] >= 0 {
			known = append(known, r)
		} else {
			rest = append(rest, r)
		}
	}
	s.shuffle(len(known), func(i, j int) { known[i], known[j] = known[j], known[i] })
	slices.SortStableFunc(known, func(a, b kolodht.Record) int { return rank[key(a.PublicKey)] - rank[key(b.PublicKey)] })
	if keep := (quota + 1) / 2; len(known) > keep {
		rest = append(rest, known[keep:]...)
		known = known[:keep]
	}
	s.shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
	order := append(known, rest...)
	// A key kept again keeps its state; a dropped one leaves it in past.
	for k, c := range prev {
		c.dropTopic(topic)
		if len(c.topics) == 0 && s.slots[k] == nil {
			delete(s.cands, k)
		}
	}
	seen := make(map[key]bool, len(order))
	for _, r := range order {
		if len(seen) >= quota {
			break
		}
		k := key(r.PublicKey)
		c := s.cands[k]
		if c == nil {
			if len(s.cands) >= s.budgetLocked() && !s.evictLocked(topic, quota) {
				continue
			}
			if c = prev[k]; c == nil {
				c = s.newCandLocked(k)
			}
			s.cands[k] = c
		}
		seen[k] = true
		if sl := s.slots[k]; sl != nil && sl.peer != nil && !slices.Contains(sl.peer.topics, topic) && s.roomLocked(topic, sl.inbound) {
			sl.peer.topics = append(sl.peer.topics, topic)
		}
		if c.addr.IsValid() && c.addr != r.Addr {
			c.next = time.Time{}
		}
		c.rec, c.addr = r, r.Addr
		if c.recs == nil {
			c.recs = make(map[Topic]kolodht.Record)
		}
		c.recs[topic] = r
		delete(c.suspect, topic)
		c.topics[topic] = true
		if prev[k] == nil {
			s.events.Push(Event{Kind: Found, Topic: topic, PublicKey: bytes.Clone(r.PublicKey), Addr: r.Addr}, classFound)
		}
	}
	for k, c := range prev {
		if s.cands[k] == nil {
			s.rememberLocked(k, c.history)
		}
	}
	s.mu.Unlock()
	s.poke()
}

// standingLocked ranks k for the known share: 0 if admitted now on an outbound place no Connect took, 1 plus its
// failures if an outbound connection lasted, else -1. Call with mu held.
func (s *Swarm) standingLocked(k key) int {
	if sl := s.slots[k]; sl != nil && sl.peer != nil && !sl.inbound && !sl.connect {
		return 0
	}
	if h := s.historyLocked(k); h != nil && h.connected {
		return 1 + h.fails
	}
	return -1
}

// historyLocked returns the state of k as a candidate or in past, or nil. Call with mu held.
func (s *Swarm) historyLocked(k key) *history {
	if c := s.cands[k]; c != nil {
		return &c.history
	}
	return s.past[k]
}

// newCandLocked returns a new candidate for k with its state from past. Call with mu held.
func (s *Swarm) newCandLocked(k key) *cand {
	c := &cand{topics: make(map[Topic]bool)}
	if h := s.past[k]; h != nil {
		c.history = *h
		delete(s.past, k)
	}
	return c
}

// dropCandLocked moves the candidate k to past. Call with mu held.
func (s *Swarm) dropCandLocked(k key) {
	if c := s.cands[k]; c != nil {
		delete(s.cands, k)
		s.rememberLocked(k, c.history)
	}
}

// rememberLocked keeps h in past unless it is a fresh state. Past grows to twice the candidate budget, then keeps the
// budget's strongest, so a trim costs O(log n) per key. Call with mu held.
func (s *Swarm) rememberLocked(k key, h history) {
	if h.fails == 0 && h.later == 0 && !h.connected && !h.dupPending && !h.relayed && !h.next.After(time.Now()) {
		return
	}
	s.past[k] = &h
	budget := s.budgetLocked()
	if len(s.past) <= 2*budget {
		return
	}
	type entry struct {
		k key
		h *history
	}
	es := make([]entry, 0, len(s.past))
	for x, p := range s.past {
		es = append(es, entry{x, p})
	}
	slices.SortFunc(es, func(a, b entry) int {
		if weaker(a.h, b.h) {
			return -1
		}
		if weaker(b.h, a.h) {
			return 1
		}
		return 0
	})
	for _, e := range es[:len(es)-budget] {
		delete(s.past, e.k)
	}
}

// dropTopic removes topic from c and the record it kept for it.
func (c *cand) dropTopic(topic Topic) {
	delete(c.topics, topic)
	delete(c.recs, topic)
	delete(c.suspect, topic)
}

// weaker orders past entries, weakest first: no lasting connection; then, among lasting ones, the most failures, and
// among others the fewest; then the soonest wait end.
func weaker(a, b *history) bool {
	switch {
	case a.connected != b.connected:
		return b.connected
	case a.fails != b.fails:
		return (a.fails < b.fails) != a.connected
	}
	return a.next.Before(b.next)
}

// shuffle uses the test's rng when set. Call with mu held.
func (s *Swarm) shuffle(n int, swap func(i, j int)) {
	if s.hooks.rng != nil {
		s.hooks.rng.Shuffle(n, swap)
		return
	}
	rand.Shuffle(n, swap)
}

// budgetLocked is the candidates kept in all: MaxCandidates, else the most of 1024, 64 per joined topic (what 1024
// gave each of 16 topics) and one per place. Call with mu held.
func (s *Swarm) budgetLocked() int {
	if s.cfg.MaxCandidates > 0 {
		return s.cfg.MaxCandidates
	}
	return max(1024, 64*s.joinedCountLocked(), s.cfg.MaxPeers)
}

// quotaLocked is each joined topic's share of the candidate budget. Call with mu held.
func (s *Swarm) quotaLocked() int {
	return max(1, s.budgetLocked()/max(1, s.joinedCountLocked()))
}

// dropCandTopicLocked removes topic from c, and c once it has no topic and no slot. Call with mu held.
func (s *Swarm) dropCandTopicLocked(k key, c *cand, topic Topic) {
	c.dropTopic(topic)
	if len(c.topics) == 0 && s.slots[k] == nil {
		s.dropCandLocked(k)
	}
}

// victimsLocked returns the candidates of topic without a slot, most failures first. Call with mu held.
func (s *Swarm) victimsLocked(topic Topic) []key {
	var ks []key
	for k, c := range s.cands {
		if c.topics[topic] && s.slots[k] == nil {
			ks = append(ks, k)
		}
	}
	s.shuffle(len(ks), func(i, j int) { ks[i], ks[j] = ks[j], ks[i] })
	slices.SortStableFunc(ks, func(a, b key) int { return s.cands[b].fails - s.cands[a].fails })
	return ks
}

func (s *Swarm) countCandsLocked(topic Topic) int {
	n := 0
	for _, c := range s.cands {
		if c.topics[topic] {
			n++
		}
	}
	return n
}

// trimLocked cuts every topic down to its share. Call with mu held.
func (s *Swarm) trimLocked() {
	quota := s.quotaLocked()
	for x := range s.topics {
		over := s.countCandsLocked(x) - quota
		for _, k := range s.victimsLocked(x) {
			if over <= 0 {
				break
			}
			s.dropCandTopicLocked(k, s.cands[k], x)
			over--
		}
	}
}

// evictLocked frees a place for topic, if under its share, from a topic over its share. Call with mu held.
func (s *Swarm) evictLocked(topic Topic, quota int) bool {
	if s.countCandsLocked(topic) >= quota {
		return false
	}
	for x := range s.topics {
		if x == topic || s.countCandsLocked(x) <= quota {
			continue
		}
		for _, k := range s.victimsLocked(x) {
			if c := s.cands[k]; len(c.topics) == 1 {
				s.dropCandLocked(k)
				return true
			}
		}
	}
	return false
}

// foundTopicsLocked returns the joined topics of also, of k's Connect slot and dials, then those our lookups found k
// on. Call with mu held.
func (s *Swarm) foundTopicsLocked(k key, also ...Topic) []Topic {
	var out []Topic
	add := func(x Topic) {
		if s.joinedLocked(x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	for _, x := range also {
		add(x)
	}
	if sl := s.slots[k]; sl != nil && sl.connect {
		add(sl.topic)
	}
	for pr, d := range s.dials {
		if pr.k == k {
			add(d.topic)
		}
	}
	if c := s.cands[k]; c != nil {
		for x := range c.topics {
			add(x)
		}
	}
	return out
}

// helloTopicsLocked is foundTopicsLocked cut to what a hello carries: the topics of also first, then those furthest
// below their fair share, where this peer counts most. Call with mu held.
func (s *Swarm) helloTopicsLocked(k key, also ...Topic) []Topic {
	out := s.foundTopicsLocked(k, also...)
	if len(out) <= hello.MaxTopics {
		return out
	}
	ta, j := s.tallyLocked(), s.joinedCountLocked()
	pinned := func(x Topic) bool { return slices.Contains(also, x) }
	slices.SortStableFunc(out, func(a, b Topic) int {
		if pa, pb := pinned(a), pinned(b); pa != pb {
			if pa {
				return -1
			}
			return 1
		}
		return cmp.Compare(int64(ta[a].total)*int64(s.shareOf(s.topics[b], j)), int64(ta[b].total)*int64(s.shareOf(s.topics[a], j)))
	})
	return out[:hello.MaxTopics]
}
