package koloswarm

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	"github.com/ciranda-dev/kolo-swarm/internal/events"
)

// placeSwarm is a unit swarm of 8 places joined to topics with Lookup, whose dials wait for their context.
func placeSwarm(t *testing.T, cfg *Config, topics ...Topic) *Swarm {
	t.Helper()
	if cfg == nil {
		cfg = &Config{MaxPeers: 8, MaxInbound: 4}
	}
	s := unitSwarm(t, cfg, topics[0])
	for _, x := range topics[1:] {
		joinUnit(s, x, 0)
	}
	s.hooks.connect = func(ctx context.Context, _ kolodht.Record) (*kolosecure.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() { s.cancel(); s.wg.Wait() })
	return s
}

// seat admits a connected peer of topics, the n-th of the test: n seconds after the first one.
func seat(t *testing.T, s *Swarm, n int, inbound bool, topics ...Topic) (key, *fake) {
	t.Helper()
	k := key(ident(t).PublicKey())
	f := newFake(k[:])
	if _, code, err := s.admit(f, k, netip.AddrPort{}, inbound, true, topics, false, generation{}); err != nil {
		t.Fatalf("admit: %d, %v", code, err)
	}
	s.mu.Lock()
	s.slots[k].peer.admitted = time.Unix(1e9, 0).Add(time.Duration(n) * time.Second)
	s.mu.Unlock()
	return k, f
}

// wanted makes n candidates of topic that the swarm may dial.
func wanted(t *testing.T, s *Swarm, topic Topic, n int) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range records(t, topic, n) {
		s.cands[key(r.PublicKey)] = &cand{rec: r, topics: map[Topic]bool{topic: true}}
	}
}

// evictedBy runs one dial pass and returns which of fs the swarm closed with codeFull, in the order of fs.
func evictedBy(t *testing.T, s *Swarm, fs ...*fake) []int {
	t.Helper()
	s.dialSome()
	time.Sleep(100 * time.Millisecond)
	var out []int
	for i, f := range fs {
		if code, ok := f.code(); ok {
			if code != codeFull {
				t.Errorf("peer %d closed with code %d, want %d", i, code, codeFull)
			}
			out = append(out, i)
		}
	}
	return out
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEvictionVictims(t *testing.T) {
	checkGoroutines(t)
	a, b := topicOf("a"), topicOf("b")
	// seatMany seats n peers of topics, inbound or not, from the n0-th on.
	seatMany := func(s *Swarm, n0, n int, inbound bool, topics ...Topic) (ks []key, fs []*fake) {
		for i := range n {
			k, f := seat(t, s, n0+i, inbound, topics...)
			ks, fs = append(ks, k), append(fs, f)
		}
		return ks, fs
	}
	t.Run("inbound first, the newest, and the evicted key is not charged", func(t *testing.T) {
		s := placeSwarm(t, nil, a, b)
		ks, fs := seatMany(s, 0, 3, true, a)
		_, ofs := seatMany(s, 3, 5, false, a)
		s.mu.Lock()
		s.cands[ks[2]] = &cand{rec: kolodht.Record{Topic: a, PublicKey: ks[2][:], Addr: fakeAddr()}, topics: map[Topic]bool{a: true}}
		s.mu.Unlock()
		for range 8 {
			if ev, ok := nextEvent(t, s); !ok || ev.Kind != Connected {
				t.Fatalf("event %v, %v", ev, ok)
			}
		}
		wanted(t, s, b, 1)
		if got := evictedBy(t, s, append(fs, ofs...)...); !sameInts(got, []int{2}) {
			t.Fatalf("closed %v, want only the newest inbound peer 2", got)
		}
		ev, ok := nextEvent(t, s)
		if !ok || ev.Kind != Lost || ev.Err != ErrClosed {
			t.Fatalf("event %+v, %v; want Lost with ErrClosed", ev, ok)
		}
		s.mu.Lock()
		c := s.cands[ks[2]]
		s.mu.Unlock()
		if c.fails != 0 || !c.next.IsZero() {
			t.Fatalf("the evicted key was charged: %d failures, wait until %v", c.fails, c.next)
		}
	})
	t.Run("a topic keeps its fair share", func(t *testing.T) {
		s := placeSwarm(t, nil, a, b)
		_, fs := seatMany(s, 0, 2, true, a)
		_, ofs := seatMany(s, 2, 3, false, a)
		_, bfs := seatMany(s, 5, 3, false, b)
		wanted(t, s, b, 2)
		if got := evictedBy(t, s, append(append(fs, ofs...), bfs...)...); !sameInts(got, []int{1}) {
			t.Fatalf("closed %v, want only the newest inbound peer 1: topic a holds 5 of its share of 4", got)
		}
	})
	t.Run("a Connect place before an outbound peer of our lookups", func(t *testing.T) {
		s := placeSwarm(t, nil, a, b)
		cks, cfs := seatMany(s, 0, 1, false, a)
		_, ofs := seatMany(s, 1, 7, false, a)
		s.mu.Lock()
		s.slots[cks[0]].connect = true
		s.mu.Unlock()
		wanted(t, s, b, 1)
		if got := evictedBy(t, s, append(cfs, ofs...)...); !sameInts(got, []int{0}) {
			t.Fatalf("closed %v, want only the Connect place 0", got)
		}
	})
	t.Run("never a place Connect still holds or a peer in a hello", func(t *testing.T) {
		s := placeSwarm(t, nil, a, b)
		ks, fs := seatMany(s, 0, 8, false, a)
		s.mu.Lock()
		for i, k := range ks {
			if i%2 == 0 {
				s.slots[k].reserved = true
			} else {
				s.helloKey[k] = 1
			}
		}
		s.mu.Unlock()
		wanted(t, s, b, 1)
		if got := evictedBy(t, s, fs...); len(got) != 0 {
			t.Fatalf("closed %v", got)
		}
	})
	t.Run("never a peer whose other topic would drop below its share", func(t *testing.T) {
		c := topicOf("c")
		s := placeSwarm(t, &Config{MaxPeers: 8, MaxInbound: 8}, a, b, c)
		_, fs := seatMany(s, 0, 5, true, a)
		_, sfs := seatMany(s, 5, 1, true, a, b)
		_, bfs := seatMany(s, 6, 1, false, b)
		_, cfs := seatMany(s, 7, 1, false, c)
		wanted(t, s, c, 1)
		if got := evictedBy(t, s, append(append(append(fs, sfs...), bfs...), cfs...)...); !sameInts(got, []int{4}) {
			t.Fatalf("closed %v, want only peer 4, the newest inbound peer that shares no other topic at its share", got)
		}
	})
}

func TestOutboundMinimum(t *testing.T) {
	checkGoroutines(t)
	a, b := topicOf("a"), topicOf("b")
	s := placeSwarm(t, &Config{MaxPeers: 8, MaxInbound: 4, MaxConnecting: 4}, a, b)
	var fs []*fake
	for i := range 4 {
		_, f := seat(t, s, i, true, b)
		fs = append(fs, f)
	}
	for i := range 4 {
		_, f := seat(t, s, 4+i, false, a)
		fs = append(fs, f)
	}
	wanted(t, s, b, 4)
	if got := evictedBy(t, s, fs...); !sameInts(got, []int{0, 1, 2, 3}) {
		t.Fatalf("closed %v, want the four inbound peers of b", got)
	}
	s.mu.Lock()
	n := s.tallyLocked()[b]
	s.mu.Unlock()
	if n.total != 4 || n.inbound != 0 || n.out != 4 {
		t.Fatalf("topic b holds %+v, want 4 outbound places", n)
	}
}

// peersOf counts the peers w sees that share topic.
func peersOf(w *watcher, topic Topic) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, p := range w.peers {
		if slices.Contains(p.Topics(), topic) {
			n++
		}
	}
	return n
}

// TestFairShareStarvingTopic: a hub of 4 places filled by one topic still gets peers for a second topic it joins later.
func TestFairShareStarvingTopic(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	srv := newServer(t)
	big, small := topicOf("big"), topicOf("small")
	for range 8 {
		join(t, newSwarm(t, srv, nil, nil), big, &JoinOptions{Announce: true})
	}
	for range 2 {
		join(t, newSwarm(t, srv, nil, nil), small, &JoinOptions{Announce: true})
	}
	cfg := fastConfig()
	cfg.MaxPeers = 4
	hub := newSwarm(t, srv, nil, cfg)
	w := watch(t, hub)
	join(t, hub, big, &JoinOptions{Lookup: true})
	waitFor(t, 10*time.Second, "4 peers of big", func() bool { return peersOf(w, big) == 4 })
	join(t, hub, small, &JoinOptions{Lookup: true})
	stable(t, 20*time.Second, time.Second, "2 peers of each topic", func() bool { return peersOf(w, big) == 2 && peersOf(w, small) == 2 })
}

// TestJoinManyTopics: a swarm with the default MaxTopics joins 50 topics, each with one peer.
func TestJoinManyTopics(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	srv := newServer(t)
	topics := make([]Topic, 50)
	owner := map[string]Topic{}
	for i := range topics {
		topics[i] = topicOf("many " + string(rune('A'+i)))
		s := newSwarm(t, srv, nil, nil)
		join(t, s, topics[i], &JoinOptions{Announce: true})
		owner[string(s.PublicKey())] = topics[i]
		time.Sleep(110 * time.Millisecond)
	}
	hub := newSwarm(t, srv, nil, nil)
	w := watch(t, hub)
	start := time.Now()
	for i, x := range topics {
		if err := hub.Join(testCtx(t, 30*time.Second), x, nil); err != nil {
			t.Fatalf("Join %d: %v", i+1, err)
		}
	}
	joined := time.Since(start)
	waitFor(t, 60*time.Second, "a peer for each of 50 topics", func() bool { return w.count() == 50 })
	t.Logf("50 topics joined in %v, 50 peers connected after %v", joined, time.Since(start))
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, p := range w.peers {
		if got := p.Topics(); len(got) != 1 || got[0] != owner[k] {
			t.Errorf("peer topics %v, want its own topic", got)
		}
	}
}

func TestCandidateBudget(t *testing.T) {
	a := topicOf("a")
	s := placeSwarm(t, &Config{MaxPeers: 1258}, a)
	s.mu.Lock()
	defer s.mu.Unlock()
	if got := s.budgetLocked(); got != 1258 {
		t.Fatalf("budget of one topic = %d, want one per place", got)
	}
	for i := range 49 {
		joinUnit(s, topicOf(string(rune('b'+i))), 0)
	}
	if got, q := s.budgetLocked(), s.quotaLocked(); got != 3200 || q != 64 {
		t.Fatalf("budget of 50 topics = %d, share %d; want 3200 and 64", got, q)
	}
	s.cfg.MaxCandidates = 100
	if got, q := s.budgetLocked(), s.quotaLocked(); got != 100 || q != 2 {
		t.Fatalf("a MaxCandidates of 100 gave %d, share %d", got, q)
	}
}

func TestPlaceBudgetShares(t *testing.T) {
	a, b := topicOf("a"), topicOf("b")
	s := placeSwarm(t, &Config{MaxPeers: 1258}, a, b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if got := s.shareOf(s.topics[a], 50); got != 25 {
		t.Fatalf("share of 50 topics over 1258 places = %d, want 25", got)
	}
	if got := s.minOutOf(s.topics[a], 50); got != 6 {
		t.Fatalf("outbound minimum = %d, want 6", got)
	}
	if got := s.minOutOf(s.topics[a], 400); got != 3 {
		t.Fatalf("outbound minimum with a share of 3 = %d, want 3", got)
	}
	s.topics[a].opts.Lookup = false
	if got := s.minOutOf(s.topics[a], 50); got != 0 {
		t.Fatalf("outbound minimum without Lookup = %d, want 0", got)
	}
}

// BenchmarkDialSome measures one pass with every place taken and 3200 candidates over 50 topics, the case of the
// default places.
func BenchmarkDialSome(b *testing.B) {
	topics := make([]Topic, 50)
	for i := range topics {
		topics[i] = topicOf(string(rune('a'+i%26)) + string(rune('A'+i/26)))
	}
	cfg := &Config{}
	c, err := cfg.withDefaults()
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Swarm{cfg: c, ctx: ctx, cancel: cancel, events: events.New[Event](c.MaxEvents, c.MaxEvents), topics: map[Topic]*topicState{}, slots: map[key]*slot{}, helloKey: map[key]int{}, cands: map[key]*cand{}, past: map[key]*history{}, wake: make(chan struct{}, 1)}
	for _, x := range topics {
		s.topics[x] = &topicState{opts: JoinOptions{Lookup: true}, ctx: ctx, cancel: func() {}}
	}
	// 25 peers a topic, 13 outbound and 12 inbound, and one more in the first 8 topics fill the 1258 places.
	for i, x := range topics {
		for j := range 25 + min(1, max(0, 8-i)) {
			k := key(ident(b).PublicKey())
			f := newFake(k[:])
			if _, _, err := s.admit(f, k, netip.AddrPort{}, j < 12, true, []Topic{x}, false, generation{}); err != nil {
				b.Fatal(i, j, err)
			}
		}
	}
	for i := range 3200 {
		k := key(ident(b).PublicKey())
		s.cands[k] = &cand{rec: kolodht.Record{Topic: topics[i%50], PublicKey: k[:], Addr: fakeAddr()}, topics: map[Topic]bool{topics[i%50]: true}}
	}
	b.ResetTimer()
	for range b.N {
		s.dialSome()
	}
}
