package koloswarm

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
)

// knownKeys makes lasted keys whose 20s outbound connection ended and admitted keys connected now, within the share.
func knownKeys(t *testing.T, s *Swarm, topic Topic, lasted, admitted int) (l, a []kolodht.Record) {
	t.Helper()
	l, a = records(t, topic, lasted), records(t, topic, admitted)
	s.found(topic, s.topics[topic], append(append([]kolodht.Record(nil), l...), a...))
	for i, r := range append(append([]kolodht.Record(nil), l...), a...) {
		k := key(r.PublicKey)
		f := newFake(r.PublicKey)
		if _, _, err := s.admit(f, k, netip.AddrPort{}, false, true, []Topic{topic}, false, generation{}); err != nil {
			t.Fatal(err)
		}
		if i >= lasted {
			continue
		}
		s.mu.Lock()
		s.slots[k].peer.admitted = time.Now().Add(-20 * time.Second)
		s.mu.Unlock()
		f.peerClose(codeNormal)
		for deadline := time.Now().Add(time.Second); ; time.Sleep(time.Millisecond) {
			s.mu.Lock()
			freed := s.slots[k] == nil
			s.mu.Unlock()
			if freed {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("slot not freed")
			}
		}
	}
	return l, a
}

func isCand(s *Swarm, topic Topic, r kolodht.Record) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cands[key(r.PublicKey)]
	return c != nil && c.topics[topic]
}

// TestKnownKeptAgainstFlood: lasting and admitted keys keep half the share against a flood of fresh records.
func TestKnownKeptAgainstFlood(t *testing.T) {
	checkGoroutines(t)
	a, b := topicOf("A"), topicOf("B")
	for range 50 {
		s := unitSwarm(t, &Config{MaxCandidates: 32}, a)
		joinUnit(s, b, 8)
		lasted, admitted := knownKeys(t, s, a, 5, 3)
		known := append(lasted, admitted...)
		s.found(a, s.topics[a], append(records(t, a, 64), known...))
		for _, r := range known {
			if !isCand(s, a, r) {
				t.Fatal("a known key dropped for a flood of fresh records")
			}
		}
		if n := s.countCandsLocked(a); n != 16 {
			t.Fatalf("%d candidates, want the share of 16", n)
		}
	}
}

// TestKnownOrder: past half of the share, keys admitted now come first, then lasting connections with fewer failures.
func TestKnownOrder(t *testing.T) {
	checkGoroutines(t)
	a := topicOf("A")
	worstDropped := false
	for range 50 {
		s := unitSwarm(t, &Config{MaxCandidates: 16}, a)
		for i := range 3 {
			joinUnit(s, topicOf(fmt.Sprint("other ", i)), 8)
		}
		lasted, admitted := knownKeys(t, s, a, 2, 1)
		s.mu.Lock()
		s.cands[key(lasted[0].PublicKey)].fails = 5
		s.mu.Unlock()
		s.found(a, s.topics[a], append(records(t, a, 64), append(lasted, admitted...)...))
		if !isCand(s, a, admitted[0]) || !isCand(s, a, lasted[1]) {
			t.Fatal("of a share of 4, the admitted key and the lasting key with 1 failure are not both kept")
		}
		if !isCand(s, a, lasted[0]) {
			worstDropped = true
		}
	}
	if !worstDropped {
		t.Fatal("the lasting key with 5 failures was always kept ahead of the sample")
	}
}

// TestQuotaOne: a share of one place goes to a known key when the lookup returns one, else to a uniform draw.
func TestQuotaOne(t *testing.T) {
	checkGoroutines(t)
	a := topicOf("A")
	share := func() *Swarm {
		s := unitSwarm(t, &Config{MaxCandidates: 16}, a)
		for i := range 15 {
			joinUnit(s, topicOf(fmt.Sprint("other ", i)), 8)
		}
		return s
	}
	for _, lasting := range []bool{true, false} {
		s := share()
		var known kolodht.Record
		if lasting {
			l, _ := knownKeys(t, s, a, 1, 0)
			known = l[0]
		} else {
			_, ad := knownKeys(t, s, a, 0, 1)
			known = ad[0]
		}
		for range 50 {
			s.found(a, s.topics[a], append(records(t, a, 20), known))
			if !isCand(s, a, known) || s.countCandsLocked(a) != 1 {
				t.Fatalf("lasting %v: the known key lost the only place", lasting)
			}
		}
	}
	s := share()
	fresh := records(t, a, 20)
	picked := map[key]bool{}
	for range 50 {
		s.found(a, s.topics[a], fresh)
		if s.countCandsLocked(a) != 1 {
			t.Fatal("a share of one holds more or less than one key")
		}
		for k := range s.cands {
			picked[k] = true
		}
	}
	if len(picked) < 2 {
		t.Fatal("without a known key the one place never changes")
	}
}

// TestBackoffSurvivesDrop: a failing key keeps its failures and its wait however often it leaves the candidates.
func TestBackoffSurvivesDrop(t *testing.T) {
	a := topicOf("A")
	s := unitSwarm(t, &Config{MaxCandidates: 16}, a)
	s.hooks.rng = rand.New(rand.NewPCG(5, 6))
	bad := records(t, a, 1)[0]
	k := key(bad.PublicKey)
	s.found(a, s.topics[a], []kolodht.Record{bad})
	next := time.Now().Add(time.Hour)
	s.cands[k].fails, s.cands[k].next = 5, next
	flood := records(t, a, 200)
	back, gone := 0, false
	for range 100 {
		s.found(a, s.topics[a], append(append([]kolodht.Record(nil), flood...), bad))
		c := s.cands[k]
		if c == nil {
			gone = true
			continue
		}
		if gone {
			back++
		}
		if c.fails != 5 || !c.next.Equal(next) {
			t.Fatalf("back after a drop with fails %d and wait %v, want 5 and the hour", c.fails, time.Until(c.next).Round(time.Minute))
		}
	}
	if back == 0 {
		t.Fatal("the key never came back after a drop")
	}
	// Back at a new address after a drop: the wait ends and the failures stay.
	s.found(a, s.topics[a], records(t, a, 1))
	moved := bad
	moved.Addr = netip.MustParseAddrPort("198.51.100.8:4000")
	s.found(a, s.topics[a], []kolodht.Record{moved})
	if c := s.cands[k]; c == nil || c.fails != 5 || !c.next.IsZero() {
		t.Fatal("a new address after a drop did not end the wait, or lost the failures")
	}
	// Dropped by the trim of a Join, or evicted for a topic under its share, a key keeps its state too.
	for _, evict := range []bool{false, true} {
		s := unitSwarm(t, &Config{MaxCandidates: 16}, a)
		recs := records(t, a, 16)
		s.found(a, s.topics[a], recs)
		k := key(recs[0].PublicKey)
		s.cands[k].fails, s.cands[k].next = 5, next
		b := topicOf("B")
		joinUnit(s, b, 8)
		if evict {
			s.found(b, s.topics[b], records(t, b, 1))
		} else {
			s.trimLocked()
		}
		if s.cands[k] != nil {
			t.Fatalf("evict %v: the key with the most failures was not dropped", evict)
		}
		s.found(a, s.topics[a], recs[:1])
		if c := s.cands[k]; c == nil || c.fails != 5 || !c.next.Equal(next) {
			t.Fatalf("evict %v: the key lost its state", evict)
		}
	}
	// A dial that fails after a lookup dropped its key still counts.
	r := records(t, a, 1)[0]
	k2 := key(r.PublicKey)
	s.found(a, s.topics[a], []kolodht.Record{r})
	s.cands[k2].fails = 3
	sl := &slot{topic: a}
	s.slots[k2] = sl
	s.found(a, s.topics[a], records(t, a, 1))
	s.release(k2, sl, releaseFailed)
	s.found(a, s.topics[a], []kolodht.Record{r})
	if c := s.cands[k2]; c == nil || c.fails != 4 || !c.next.After(time.Now()) {
		t.Fatal("a failed dial of a dropped key was forgotten")
	}
}

// TestForgedAddress: records that claim an honest key's address, as a malicious server can return, do not crowd it out.
func TestForgedAddress(t *testing.T) {
	a := topicOf("A")
	addr := netip.MustParseAddrPort("198.51.100.7:4000")
	h := kolodht.Record{Topic: a, PublicKey: ident(t).PublicKey(), Addr: addr}
	var forged []kolodht.Record
	for i := range 20 {
		port := addr.Port()
		if i%2 == 1 {
			port += uint16(i)
		}
		forged = append(forged, kolodht.Record{Topic: a, PublicKey: ident(t).PublicKey(), Addr: netip.AddrPortFrom(addr.Addr(), port)})
	}
	for range 100 {
		s := unitSwarm(t, nil, a)
		s.found(a, s.topics[a], append(append([]kolodht.Record(nil), forged...), h))
		if !isCand(s, a, h) {
			t.Fatal("the honest key crowded out by records claiming its address")
		}
	}
	// In a lookup larger than the share it has the odds of any other fresh key: 16 places for 65 records.
	others := records(t, a, 44)
	const runs = 400
	kept := 0
	for range runs {
		s := unitSwarm(t, &Config{MaxCandidates: 32}, a)
		joinUnit(s, topicOf("B"), 8)
		s.found(a, s.topics[a], append(append(append([]kolodht.Record(nil), forged...), others...), h))
		if isCand(s, a, h) {
			kept++
		}
	}
	if f := float64(kept) / runs; f < 0.15 {
		t.Fatalf("the honest key kept in %.2f of lookups, want about 0.25", f)
	}
}

// TestKnownAfterDrop: a key whose lasting outbound connection ended after a lookup dropped it is still known.
func TestKnownAfterDrop(t *testing.T) {
	checkGoroutines(t)
	a, b := topicOf("A"), topicOf("B")
	s := unitSwarm(t, &Config{MaxCandidates: 32}, a)
	joinUnit(s, b, 8)
	r := records(t, a, 1)[0]
	k := key(r.PublicKey)
	s.found(a, s.topics[a], []kolodht.Record{r})
	f := newFake(r.PublicKey)
	if _, _, err := s.admit(f, k, netip.AddrPort{}, false, true, []Topic{a}, false, generation{}); err != nil {
		t.Fatal(err)
	}
	s.found(a, s.topics[a], records(t, a, 1))
	s.mu.Lock()
	s.slots[k].peer.admitted = time.Now().Add(-20 * time.Second)
	s.mu.Unlock()
	f.peerClose(codeNormal)
	waitFor(t, time.Second, "slot freed", func() bool { n, _ := s.slotCounts(); return n == 0 })
	tk, _, ok := s.reserveHello(k, "ip 198.51.100.1", true, false)
	if !ok || tk.class != helloKnown {
		t.Fatalf("hello class %d, want known", tk.class)
	}
	s.releaseHello(tk)
	for range 20 {
		s.found(a, s.topics[a], append(records(t, a, 64), r))
		if !isCand(s, a, r) {
			t.Fatal("the key lost its preference with its candidate entry")
		}
	}
}

// TestDialConnectedFirst: a key whose outbound connection lasted, in the state lost leaves it (fails 1), is dialed
// before a key with as many failures and before fresh keys.
func TestDialConnectedFirst(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("dial order")
	for range 20 {
		var mu sync.Mutex
		var first ed25519.PublicKey
		cfg := fastConfig()
		cfg.MaxConnecting = 1
		cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool {
			mu.Lock()
			defer mu.Unlock()
			if first == nil {
				first = k
			}
			return false
		}
		s := newSwarm(t, nil, nil, cfg)
		join(t, s, topic, &JoinOptions{Lookup: true})
		recs := records(t, topic, 6)
		s.mu.Lock()
		for i, r := range recs {
			c := &cand{rec: r, topics: map[Topic]bool{topic: true}}
			if i < 2 {
				c.fails, c.connected = 1, i == 1
			}
			s.cands[key(r.PublicKey)] = c
		}
		s.mu.Unlock()
		s.poke()
		waitFor(t, 2*time.Second, "a dial", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return first != nil
		})
		if string(first) != string(recs[1].PublicKey) {
			t.Fatal("a key without a lasting connection was dialed first")
		}
		s.Close()
	}
}

// TestDupPendingAfterDrop: a duplicate close still pending when its key leaves the candidates counts as a failure.
func TestDupPendingAfterDrop(t *testing.T) {
	a := topicOf("A")
	s := unitSwarm(t, nil, a)
	r := records(t, a, 1)[0]
	k := key(r.PublicKey)
	s.found(a, s.topics[a], []kolodht.Record{r})
	sl := &slot{topic: a}
	s.slots[k] = sl
	tk, _, ok := s.reserveHello(k, "ip 198.51.100.1", true, false)
	if !ok {
		t.Fatal("no hello")
	}
	s.release(k, sl, releaseDuplicate)
	s.found(a, s.topics[a], records(t, a, 1))
	if s.cands[k] != nil {
		t.Fatal("the key is still a candidate")
	}
	s.releaseHello(tk)
	s.found(a, s.topics[a], []kolodht.Record{r})
	if c := s.cands[k]; c == nil || c.fails != 1 {
		t.Fatal("the pending duplicate close was not counted")
	}
}

// TestPastBounded: past holds at most twice MaxCandidates keys, then keeps the MaxCandidates strongest: lasting
// connections with the fewest failures, then the most failures, then the latest wait. A fresh state is not stored.
func TestPastBounded(t *testing.T) {
	a := topicOf("A")
	newKey := func() key { return key(ident(t).PublicKey()) }
	fill := func(s *Swarm, n int, h history) {
		for range n {
			s.rememberLocked(newKey(), h)
		}
	}
	s := unitSwarm(t, &Config{MaxCandidates: 16}, a)
	s.rememberLocked(newKey(), history{next: time.Now().Add(-time.Second)})
	if len(s.past) != 0 {
		t.Fatal("a key without failures, wait or lasting connection was stored")
	}
	reliable, flaky := newKey(), newKey()
	s.rememberLocked(reliable, history{connected: true, fails: 1})
	s.rememberLocked(flaky, history{connected: true, fails: 9})
	fill(s, 15, history{connected: true, fails: 5})
	fill(s, 15, history{fails: 9})
	if n := len(s.past); n != 32 {
		t.Fatalf("past holds %d keys, want up to twice MaxCandidates", n)
	}
	fill(s, 1, history{fails: 9})
	if n := len(s.past); n != 16 {
		t.Fatalf("past holds %d keys after its trim, want MaxCandidates", n)
	}
	if s.past[reliable] == nil || s.past[flaky] != nil {
		t.Fatal("of two lasting connections, the one with more failures was kept")
	}
	for _, h := range s.past {
		if !h.connected {
			t.Fatal("a key without a lasting connection kept over one with")
		}
	}
	s = unitSwarm(t, &Config{MaxCandidates: 16}, a)
	many, late := newKey(), newKey()
	s.rememberLocked(many, history{fails: 9})
	fill(s, 14, history{fails: 3})
	s.rememberLocked(late, history{fails: 1, next: time.Now().Add(2 * time.Minute)})
	fill(s, 17, history{fails: 1, next: time.Now().Add(time.Minute)})
	if len(s.past) != 16 || s.past[many] == nil || s.past[late] == nil {
		t.Fatal("past did not keep the most failures, then the latest wait")
	}
}

// TestPastCost: dropping keys into a past at twice MaxCandidates trims it once, not with a scan per key.
func TestPastCost(t *testing.T) {
	a := topicOf("A")
	s := unitSwarm(t, &Config{MaxCandidates: 32768}, a)
	for i := range 2 * 32768 {
		var k key
		k[0], k[1], k[2], k[3] = byte(i), byte(i>>8), byte(i>>16), 0xee
		s.past[k] = &history{fails: 2 + i%5, next: time.Now().Add(time.Hour)}
	}
	s.found(a, s.topics[a], records(t, a, 1000))
	for _, c := range s.cands {
		c.fails = 1
	}
	start := time.Now()
	s.found(a, s.topics[a], nil)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("dropping 1000 keys into a full past took %v", d)
	}
	if n := len(s.past); n >= 2*32768 {
		t.Fatalf("past holds %d keys: no trim ran", n)
	}
}

// TestInboundNotKnown: a key admitted on a connection it opened gets no place in the known share.
func TestInboundNotKnown(t *testing.T) {
	a := topicOf("A")
	dropped := false
	for range 50 {
		s := unitSwarm(t, &Config{MaxCandidates: 16}, a)
		for i := range 3 {
			joinUnit(s, topicOf(fmt.Sprint("other ", i)), 8)
		}
		r := records(t, a, 1)[0]
		k := key(r.PublicKey)
		s.found(a, s.topics[a], []kolodht.Record{r})
		if _, _, err := s.admit(newFake(r.PublicKey), k, netip.AddrPort{}, true, true, []Topic{a}, false, generation{}); err != nil {
			t.Fatal(err)
		}
		s.found(a, s.topics[a], append(records(t, a, 64), r))
		if !isCand(s, a, r) {
			dropped = true
		}
	}
	if !dropped {
		t.Fatal("an inbound peer was always kept ahead of the sample")
	}
}

// TestAdmitClearsPastDup: a duplicate close pending for a key in past is not a failure once a connection to it is admitted.
func TestAdmitClearsPastDup(t *testing.T) {
	checkGoroutines(t)
	a := topicOf("A")
	s := unitSwarm(t, nil, a)
	r := records(t, a, 1)[0]
	k := key(r.PublicKey)
	s.found(a, s.topics[a], []kolodht.Record{r})
	sl := &slot{topic: a}
	s.slots[k] = sl
	tk, _, ok := s.reserveHello(k, "ip 198.51.100.1", true, false)
	if !ok {
		t.Fatal("no hello")
	}
	s.release(k, sl, releaseDuplicate)
	s.found(a, s.topics[a], records(t, a, 1))
	f := newFake(r.PublicKey)
	if _, _, err := s.admit(f, k, netip.AddrPort{}, true, true, []Topic{a}, false, generation{}); err != nil {
		t.Fatal(err)
	}
	f.peerClose(codeNormal)
	waitFor(t, time.Second, "slot freed", func() bool { n, _ := s.slotCounts(); return n == 0 })
	s.releaseHello(tk)
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.past[k]; h == nil || h.fails != 0 {
		t.Fatal("a duplicate close counted as a failure after an admission")
	}
}

// TestDialOnePerAddr: two candidates whose records share an IPv4 host, on any port, are not dialed at once, in one
// pass or the next, so records a server forges at a peer's host cannot take the sessions kolo-dht opens toward it.
func TestDialOnePerAddr(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("one per addr")
	var mu sync.Mutex
	inflight := map[string]bool{}
	unblock := make(chan struct{})
	cfg := fastConfig()
	cfg.MaxConnecting = 3
	cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool {
		mu.Lock()
		inflight[string(k)] = true
		mu.Unlock()
		<-unblock
		return false
	}
	s := newSwarm(t, nil, nil, cfg)
	t.Cleanup(func() { close(unblock) })
	join(t, s, topic, &JoinOptions{Lookup: true})
	recs := records(t, topic, 3)
	recs[0].Addr, recs[1].Addr = netip.MustParseAddrPort("198.51.100.7:4000"), netip.MustParseAddrPort("198.51.100.7:4001")
	s.mu.Lock()
	for _, r := range recs {
		s.cands[key(r.PublicKey)] = &cand{rec: r, topics: map[Topic]bool{topic: true}, history: history{addr: r.Addr}}
	}
	s.mu.Unlock()
	s.poke()
	waitFor(t, 2*time.Second, "two dials", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(inflight) >= 2
	})
	for pass := range 2 {
		time.Sleep(200 * time.Millisecond)
		mu.Lock()
		both, other := inflight[string(recs[0].PublicKey)] && inflight[string(recs[1].PublicKey)], inflight[string(recs[2].PublicKey)]
		mu.Unlock()
		if both {
			t.Fatalf("pass %d: two records at one host dialed at once", pass)
		}
		if !other {
			t.Fatal("the record at another host was not dialed")
		}
		s.poke()
	}
}

// TestConnectRelease: kolo-dht's ErrTryLater (a punch budget, or kolo-dht busy toward the address) delays the key
// without counting a failure; ErrInvalidArgument waits a lookup; other errors are failures.
func TestConnectRelease(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want int
	}{
		{kolodht.ErrTryLater, releaseLater},
		{fmt.Errorf("x: %w", kolodht.ErrTryLater), releaseLater},
		{kolodht.ErrUnreachable, releaseFailed},
		{kolodht.ErrInvalidArgument, releaseDenied},
		{errors.New("other"), releaseFailed},
	} {
		if got := connectRelease(tt.err); got != tt.want {
			t.Errorf("connectRelease(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
	// The first wait is kolo-dht's RandomPunchInterval, its default 20s or the configured one, and no failure counts.
	a := topicOf("A")
	for _, tt := range []struct {
		dht  *kolodht.Config
		want time.Duration
	}{{nil, 20 * time.Second}, {&kolodht.Config{RandomPunchInterval: time.Minute}, time.Minute}} {
		s := unitSwarm(t, &Config{RetryMin: time.Second, DHT: tt.dht}, a)
		r := records(t, a, 1)[0]
		k := key(r.PublicKey)
		s.found(a, s.topics[a], []kolodht.Record{r})
		s.cands[k].fails = 2
		sl := &slot{topic: a}
		s.slots[k] = sl
		s.release(k, sl, releaseLater)
		if c := s.cands[k]; c.fails != 2 || time.Until(c.next) < tt.want-time.Second {
			t.Fatalf("try later: fails %d, wait %v; want 2 and at least %v", c.fails, time.Until(c.next), tt.want)
		}
		// A second one doubles the ceiling: some of 30 second waits pass 2 × the interval, which one at the first
		// level never can.
		longer := false
		for range 30 {
			c := s.cands[k]
			c.later = 1
			sl := &slot{topic: a}
			s.slots[k] = sl
			before := time.Now()
			s.release(k, sl, releaseLater)
			longer = longer || c.next.Sub(before) > 2*tt.want
		}
		if !longer {
			t.Fatal("a second ErrTryLater never waited past twice the interval")
		}
		// An admission ends the count.
		if _, _, err := s.admit(newFake(r.PublicKey), k, netip.AddrPort{}, false, true, []Topic{a}, false, generation{}); err != nil {
			t.Fatal(err)
		}
		if s.cands[k].later != 0 {
			t.Fatal("an admission kept the ErrTryLater count")
		}
	}
}

// TestTryLaterBehindFailures: a key that keeps getting ErrTryLater sorts behind a key with one real failure.
func TestTryLaterBehindFailures(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("try later")
	for range 10 {
		var mu sync.Mutex
		var first ed25519.PublicKey
		cfg := fastConfig()
		cfg.MaxConnecting = 1
		cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool {
			mu.Lock()
			defer mu.Unlock()
			if first == nil {
				first = k
			}
			return false
		}
		s := newSwarm(t, nil, nil, cfg)
		join(t, s, topic, &JoinOptions{Lookup: true})
		recs := records(t, topic, 2)
		later, failed := key(recs[0].PublicKey), key(recs[1].PublicKey)
		s.mu.Lock()
		for _, r := range recs {
			s.cands[key(r.PublicKey)] = &cand{rec: r, topics: map[Topic]bool{topic: true}}
		}
		s.cands[failed].fails, s.cands[failed].next = 1, time.Now().Add(time.Hour)
		s.cands[later].next = time.Now().Add(time.Hour)
		s.mu.Unlock()
		for range 3 {
			sl := &slot{topic: topic}
			s.mu.Lock()
			s.slots[later] = sl
			s.mu.Unlock()
			s.release(later, sl, releaseLater)
		}
		s.mu.Lock()
		s.cands[failed].next, s.cands[later].next = time.Time{}, time.Time{}
		s.mu.Unlock()
		s.poke()
		waitFor(t, 2*time.Second, "a dial", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return first != nil
		})
		if string(first) != string(failed[:]) {
			t.Fatal("a key with three ErrTryLater was dialed before a key with one failure")
		}
		s.Close()
	}
}

// dialProbe starts a swarm whose Allow records the keys being dialed and blocks them until the test ends.
func dialProbe(t *testing.T, maxConnecting int) (*Swarm, Topic, func(kolodht.Record) bool) {
	topic := topicOf("dial probe")
	var mu sync.Mutex
	inflight := map[string]bool{}
	unblock := make(chan struct{})
	cfg := fastConfig()
	cfg.MaxConnecting = maxConnecting
	cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool {
		mu.Lock()
		inflight[string(k)] = true
		mu.Unlock()
		<-unblock
		return false
	}
	s := newSwarm(t, nil, nil, cfg)
	t.Cleanup(func() { close(unblock) })
	join(t, s, topic, &JoinOptions{Lookup: true})
	return s, topic, func(r kolodht.Record) bool {
		mu.Lock()
		defer mu.Unlock()
		return inflight[string(r.PublicKey)]
	}
}

// addCands adds ready candidates of topic at once, recs[i] with fails[i], and wakes dialSome.
func addCands(s *Swarm, topic Topic, fails []int, recs ...kolodht.Record) {
	s.mu.Lock()
	for i, r := range recs {
		s.cands[key(r.PublicKey)] = &cand{rec: r, topics: map[Topic]bool{topic: true}, history: history{addr: r.Addr, fails: fails[i]}}
	}
	s.mu.Unlock()
	s.poke()
}

// TestDialBusyRelayHost: a dial reaching host X only through a relay's stored address does not start while another
// dial reaches X; a dial whose own Addr is at X waits only for another dial whose own Addr is at X. Without a record
// at X, two dials through relays still do not reach X at once.
func TestDialBusyRelayHost(t *testing.T) {
	checkGoroutines(t)
	x := netip.MustParseAddrPort("198.51.100.7:4000")
	for _, mode := range []string{"own first", "relay first", "relays only"} {
		relayFirst := mode != "own first"
		s, topic, dialed := dialProbe(t, 4)
		recs := records(t, topic, 4)
		viaX, atX, other, viaX2 := recs[0], recs[1], recs[2], recs[3]
		viaX.Addr, atX.Addr, viaX2.Addr = netip.MustParseAddrPort("198.51.100.20:4000"), x, netip.MustParseAddrPort("198.51.100.21:4000")
		s.mu.Lock()
		s.hooks.addrsOf = func(r kolodht.Record) []netip.AddrPort {
			if string(r.PublicKey) == string(viaX.PublicKey) || string(r.PublicKey) == string(viaX2.PublicKey) {
				return []netip.AddrPort{r.Addr, netip.AddrPortFrom(x.Addr(), 5000)}
			}
			return []netip.AddrPort{r.Addr}
		}
		s.mu.Unlock()
		// One failure sorts a key after the fresh ones.
		first, late := atX, viaX
		if relayFirst {
			first, late = viaX, atX
		}
		if mode == "relays only" {
			addCands(s, topic, []int{0, 0, 1}, first, other, viaX2)
		} else {
			addCands(s, topic, []int{0, 0, 1, 1}, first, other, late, viaX2)
		}
		for pass := range 2 {
			time.Sleep(200 * time.Millisecond)
			if !dialed(first) || !dialed(other) {
				t.Fatalf("%s, pass %d: a free host was not dialed", mode, pass)
			}
			if dialed(viaX2) || (!relayFirst && dialed(viaX)) {
				t.Fatalf("%s, pass %d: a dial reached X through a relay while X was busy", mode, pass)
			}
			if mode == "relay first" && !dialed(atX) {
				t.Fatalf("pass %d: a dial through a relay kept the record at X from its own host", pass)
			}
			s.poke()
		}
	}
}

// TestDialOwnHostOverRelay: fresh records that list honest host H among their relays, a new one each pass, do not keep
// the key whose own Addr is H from being dialed, though it has a failure and sorts after them.
func TestDialOwnHostOverRelay(t *testing.T) {
	checkGoroutines(t)
	s, topic, dialed := dialProbe(t, 3)
	h := netip.MustParseAddrPort("198.51.100.7:4000")
	p := records(t, topic, 1)[0]
	p.Addr = h
	s.mu.Lock()
	s.hooks.addrsOf = func(r kolodht.Record) []netip.AddrPort {
		if r.Addr == h {
			return []netip.AddrPort{r.Addr}
		}
		return []netip.AddrPort{r.Addr, netip.AddrPortFrom(h.Addr(), 5000)}
	}
	s.mu.Unlock()
	for i := range 3 {
		f := records(t, topic, 1)[0]
		f.Addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(30 + i)}), 4000)
		if i == 0 {
			addCands(s, topic, []int{0, 1}, f, p)
		} else {
			addCands(s, topic, []int{0}, f)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !dialed(p) {
		t.Fatal("forged records through relays kept the key at its own host from being dialed")
	}
}

// TestPastKeepsLater: a key with only ErrTryLater that leaves the candidates after its wait ended comes back with its count.
func TestPastKeepsLater(t *testing.T) {
	a := topicOf("A")
	s := unitSwarm(t, nil, a)
	r := records(t, a, 1)[0]
	k := key(r.PublicKey)
	s.found(a, s.topics[a], []kolodht.Record{r})
	sl := &slot{topic: a}
	s.slots[k] = sl
	s.release(k, sl, releaseLater)
	s.cands[k].next = time.Now().Add(-time.Second)
	s.found(a, s.topics[a], records(t, a, 1))
	s.found(a, s.topics[a], []kolodht.Record{r})
	if c := s.cands[k]; c == nil || c.later != 1 || c.fails != 0 {
		t.Fatal("the ErrTryLater count was lost with the candidate")
	}
}
