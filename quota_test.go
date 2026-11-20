package koloswarm

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	"github.com/ciranda-dev/kolo-swarm/internal/hello"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func records(t *testing.T, topic Topic, n int) []kolodht.Record {
	var recs []kolodht.Record
	for range n {
		recs = append(recs, kolodht.Record{Topic: topic, PublicKey: ident(t).PublicKey(), Addr: fakeAddr()})
	}
	return recs
}

func joinUnit(s *Swarm, topic Topic, maxPeers int) {
	s.topics[topic] = &topicState{opts: JoinOptions{Lookup: true, MaxPeers: maxPeers}, ctx: s.ctx, cancel: func() {}}
}

// TestShuffledQuota: record order does not matter, and a key whose lasting connection ended always beats a flood.
func TestShuffledQuota(t *testing.T) {
	checkGoroutines(t)
	a, b := topicOf("A"), topicOf("B")
	attackers, honest := records(t, a, 16), records(t, a, 16)
	recs := append(append([]kolodht.Record(nil), attackers...), honest...)
	isHonest := map[key]bool{}
	for _, r := range honest {
		isHonest[key(r.PublicKey)] = true
	}
	kept := 0
	const runs = 200
	for range runs {
		s := unitSwarm(t, &Config{MaxCandidates: 32}, a)
		joinUnit(s, b, 8)
		s.found(a, s.topics[a], recs)
		if len(s.cands) != 16 {
			t.Fatalf("%d candidates, want the share of 16", len(s.cands))
		}
		for k := range s.cands {
			if isHonest[k] {
				kept++
			}
		}
	}
	if frac := float64(kept) / (16 * runs); frac < 0.4 || frac > 0.6 {
		t.Fatalf("honest keys are %.2f of the candidates, want about half", frac)
	}
	for range 50 {
		s := unitSwarm(t, &Config{MaxCandidates: 32}, a)
		joinUnit(s, b, 8)
		lasted, _ := knownKeys(t, s, a, 1, 0)
		s.found(a, s.topics[a], append(records(t, a, 64), lasted...))
		if !isCand(s, a, lasted[0]) {
			t.Fatal("a key whose lasting outbound connection ended was dropped for a flood")
		}
	}
}

// TestCandidateTurnover: attacker records that appear in every lookup do not take over a topic's share.
func TestCandidateTurnover(t *testing.T) {
	a := topicOf("A")
	s := unitSwarm(t, &Config{MaxCandidates: 16}, a)
	s.hooks.rng = rand.New(rand.NewPCG(3, 4))
	attackers, honest := records(t, a, 16), records(t, a, 64)
	isAttacker := map[key]bool{}
	for _, r := range attackers {
		isAttacker[key(r.PublicKey)] = true
	}
	coin := rand.New(rand.NewPCG(1, 2))
	for range 30 {
		recs := append([]kolodht.Record(nil), attackers...)
		for _, r := range honest {
			if coin.IntN(4) != 0 {
				recs = append(recs, r)
			}
		}
		s.found(a, s.topics[a], recs)
	}
	n := 0
	for k := range s.cands {
		if isAttacker[k] {
			n++
		}
	}
	if n > 8 {
		t.Fatalf("the attacker holds %d of %d candidates after 30 lookups", n, len(s.cands))
	}
}

// TestJoinTrimsCandidates: a topic that is full and never looks up again still gives up its excess on Join.
func TestJoinTrimsCandidates(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxCandidates = 16
	s := newSwarm(t, nil, nil, cfg)
	a, b := topicOf("trim A"), topicOf("trim B")
	join(t, s, a, &JoinOptions{Lookup: true, MaxPeers: 1})
	k := key(ident(t).PublicKey())
	if _, _, err := s.admit(newFake(k[:]), k, netip.AddrPort{}, false, true, []Topic{a}, false, generation{}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	ta := s.topics[a]
	s.mu.Unlock()
	s.found(a, ta, records(t, a, 16))
	join(t, s, b, &JoinOptions{Lookup: true})
	s.mu.Lock()
	n := s.countCandsLocked(a)
	tb := s.topics[b]
	s.mu.Unlock()
	if n > 8 {
		t.Fatalf("topic A kept %d candidates after Join, over its share of 8", n)
	}
	bk := ident(t).PublicKey()
	s.found(b, tb, []kolodht.Record{{Topic: b, PublicKey: bk, Addr: netip.MustParseAddrPort("127.0.0.1:10")}})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cands[key(bk)] == nil {
		t.Fatal("topic B's key is not a candidate")
	}
}

// TestEvictForTopicUnderShare: a full table gives a place to a topic under its share.
func TestEvictForTopicUnderShare(t *testing.T) {
	a, b := topicOf("A"), topicOf("B")
	s := unitSwarm(t, &Config{MaxCandidates: 16}, a)
	s.found(a, s.topics[a], records(t, a, 16))
	joinUnit(s, b, 8)
	bk := ident(t).PublicKey()
	s.found(b, s.topics[b], []kolodht.Record{{Topic: b, PublicKey: bk, Addr: netip.MustParseAddrPort("127.0.0.1:10")}})
	if s.cands[key(bk)] == nil || len(s.cands) != 16 {
		t.Fatalf("B's key kept: %v, %d candidates", s.cands[key(bk)] != nil, len(s.cands))
	}
}

// TestDupPending: a duplicate close counts as a failure once the hello in progress ends without an admission.
func TestDupPending(t *testing.T) {
	topic := topicOf("unit")
	for _, admitted := range []bool{false, true} {
		s := unitSwarm(t, nil, topic)
		k := key(ident(t).PublicKey())
		c := &cand{topics: map[Topic]bool{topic: true}}
		s.cands[k] = c
		sl := &slot{topic: topic}
		s.slots[k] = sl
		tk, _, ok := s.reserveHello(k, "ip 198.51.100.1", true, false)
		if !ok {
			t.Fatal("no hello")
		}
		s.release(k, sl, releaseDuplicate)
		if c.fails != 0 || !c.dupPending {
			t.Fatalf("with a hello in progress: fails %d, pending %v", c.fails, c.dupPending)
		}
		if admitted {
			if _, _, err := s.admit(newFake(k[:]), k, netip.AddrPort{}, true, true, []Topic{topic}, false, generation{}); err != nil {
				t.Fatal(err)
			}
		}
		s.releaseHello(tk)
		want := 1
		if admitted {
			want = 0
		}
		if c.fails != want || c.dupPending {
			t.Fatalf("admitted %v: fails %d, want %d (pending %v)", admitted, c.fails, want, c.dupPending)
		}
	}
}

// TestDupDialBack: a peer that dials back silently before closing with code 2 still gets growing delays.
func TestDupDialBack(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("dial back")
	cfg := fastConfig()
	cfg.RetryMin, cfg.RetryMax = 200*time.Millisecond, 10*time.Second
	var s *Swarm
	var ready sync.WaitGroup
	ready.Add(1)
	atkID := ident(t)
	var mu sync.Mutex
	var backs []*kolosecure.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range backs {
			c.Close()
		}
	})
	newRawNode(t, srv, atkID, topic, func(c *kolosecure.Conn) {
		ready.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if back, err := kolosecure.Dial(ctx, s.Addr().String(), atkID, s.PublicKey(), nil); err == nil {
			mu.Lock()
			backs = append(backs, back)
			mu.Unlock()
			k := key(atkID.PublicKey())
			for ctx.Err() == nil {
				s.mu.Lock()
				inHello := s.helloKey[k] > 1 // our dial's hello and the dial-back's
				s.mu.Unlock()
				if inHello {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		c.CloseWithError(codeDuplicate, "")
	})
	s = newSwarm(t, srv, nil, cfg)
	ready.Done()
	join(t, s, topic, &JoinOptions{Lookup: true})
	k := key(atkID.PublicKey())
	waitFor(t, 15*time.Second, "failures counted", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		c := s.cands[k]
		return c != nil && c.fails >= 2
	})
}

func TestEpochReplacement(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, nil, topic)
	k := key(ident(t).PublicKey())
	old, restarted, stale := newFake(k[:]), newFake(k[:]), newFake(k[:])
	if _, _, err := s.admit(old, k, netip.AddrPort{}, false, true, []Topic{topic}, true, generation{epoch: 1, n: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.admit(restarted, k, netip.AddrPort{}, false, true, []Topic{topic}, true, generation{epoch: 2, n: 5}); err != nil {
		t.Fatalf("a restarted arbiter's connection refused: %v", err)
	}
	if old.ctx.Err() == nil {
		t.Fatal("old connection kept")
	}
	if _, _, err := s.admit(stale, k, netip.AddrPort{}, false, true, []Topic{topic}, true, generation{epoch: 2, n: 4}); err == nil {
		t.Fatal("a lower generation of the same epoch admitted")
	}
}

func TestConnectedBefore(t *testing.T) {
	topic := topicOf("unit")
	tests := []struct {
		inbound bool
		age     time.Duration
		want    bool
	}{
		{false, 20 * time.Second, true},
		{false, time.Second, false},
		{true, 20 * time.Second, false},
	}
	for _, tt := range tests {
		s := unitSwarm(t, nil, topic)
		k := key(ident(t).PublicKey())
		c := &cand{topics: map[Topic]bool{topic: true}}
		s.cands[k] = c
		f := newFake(k[:])
		if _, _, err := s.admit(f, k, netip.AddrPort{}, tt.inbound, true, []Topic{topic}, false, generation{}); err != nil {
			t.Fatal(err)
		}
		if c.connected {
			t.Fatal("connected set at admission")
		}
		s.mu.Lock()
		s.slots[k].peer.admitted = time.Now().Add(-tt.age)
		s.mu.Unlock()
		f.peerClose(codeNormal)
		waitFor(t, time.Second, "slot freed", func() bool { n, _ := s.slotCounts(); return n == 0 })
		s.mu.Lock()
		got := c.connected
		s.mu.Unlock()
		if got != tt.want {
			t.Errorf("inbound %v, lasted %v: connected %v, want %v", tt.inbound, tt.age, got, tt.want)
		}
	}
}

func TestReleaseDuplicateDelay(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, &Config{RetryMin: 100 * time.Millisecond, RetryMax: time.Minute}, topic)
	k := key(ident(t).PublicKey())
	c := &cand{topics: map[Topic]bool{topic: true}}
	s.cands[k] = c
	for n := 1; n <= 4; n++ {
		sl := &slot{topic: topic}
		s.slots[k] = sl
		before := time.Now()
		s.release(k, sl, releaseDuplicate)
		if c.fails != n {
			t.Fatalf("after %d duplicate closes fails = %d", n, c.fails)
		}
		low, high := before.Add(100*time.Millisecond), time.Now().Add(100*time.Millisecond<<n)
		if c.next.Before(low) || !c.next.Before(high) {
			t.Fatalf("after %d: wait %v, want within [100ms, %v)", n, c.next.Sub(before), 100*time.Millisecond<<n)
		}
	}
}

func TestLostErrQUICRefused(t *testing.T) {
	if got := lostErr(&kolotransport.Error{Err: kolotransport.ErrRefused, Code: codeDuplicate}); got != ErrLost {
		t.Fatalf("QUIC CONNECTION_REFUSED mapped to %v", got)
	}
}

// blockingOpen is a Conn whose OpenStream waits until its context ends, as when the peer allows no stream.
type blockingOpen struct{ *fake }

func (b blockingOpen) OpenStream(ctx context.Context) (*kolotransport.Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestOpenStreamWindow: a peer that never lets the non-arbiter open the hello stream holds it about 2s, not HelloTimeout.
func TestOpenStreamWindow(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.HelloTimeout = 10 * time.Second
	s := newSwarm(t, nil, nil, cfg)
	join(t, s, topicOf("open"), &JoinOptions{Lookup: true})
	var id *koloid.Identity
	for id == nil || string(id.PublicKey()) > string(s.PublicKey()) {
		id = ident(t)
	}
	start := time.Now()
	err := s.Attach(testCtx(t, 15*time.Second), blockingOpen{newFake(id.PublicKey())}, true)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Attach returned after %v", d)
	}
	if err != ErrProtocol {
		t.Fatalf("Attach = %v, want ErrProtocol", err)
	}
}

// TestReplyNoCredit: a peer that gives no flow-control credit cannot hold the arbiter's hello, since the reply is
// queued without credit; so the reply needs no window of its own.
func TestReplyNoCredit(t *testing.T) {
	checkGoroutines(t)
	small, large := identPair(t)
	cfg := fastConfig()
	cfg.HelloTimeout = 10 * time.Second
	s := newSwarm(t, nil, small, cfg)
	topic := topicOf("reply window")
	join(t, s, topic, &JoinOptions{Lookup: true})
	ctx := testCtx(t, 20*time.Second)
	tight := &kolosecure.Config{Transport: &kolotransport.Config{MaxStreamReceiveWindow: 64 << 10, MaxConnReceiveWindow: 64 << 10}}
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", large, tight)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	accepted := make(chan *kolosecure.Conn, 1)
	go func() {
		c, _ := l.Accept(ctx)
		accepted <- c
	}()
	mine, err := kolosecure.Dial(ctx, l.Addr().String(), small, large.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mine.Close() })
	peer := <-accepted
	if peer == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { peer.Close() })
	// Use up the peer's connection window with a stream it never reads, so nothing more can be sent to it.
	fill, err := mine.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fill.SetWriteDeadline(time.Now().Add(time.Second))
	if n, _ := fill.Write(make([]byte, 1<<20)); n == 1<<20 {
		t.Fatal("the peer's window took 1 MiB")
	}
	errc := make(chan error, 1)
	go func() { errc <- s.Attach(ctx, mine, true) }()
	start := time.Now()
	send(t, peer, encodeRaw(t, topic), false)
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("the arbiter still holds the hello after 5s")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the hello was held %v", d.Round(100*time.Millisecond))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hellos != 0 {
		t.Fatal("the hello slot is still taken")
	}
}

// TestReplyAfterWindow: a reply written after the hello window ended, here because the test holds it, still reaches
// the peer, and the connection it admitted stays after replacing the older one.
func TestReplyAfterWindow(t *testing.T) {
	checkGoroutines(t)
	s, w, topic := helloSwarm(t, nil)
	var hold atomic.Bool
	s.hooks.beforeReply = func() {
		if hold.Load() {
			time.Sleep(300 * time.Millisecond)
		}
	}
	id := sides(t, s, true)
	old := rawPeer(t, s, id)
	if len(send(t, old, encodeRaw(t, topic), true)) == 0 {
		t.Fatal("no reply on the first connection")
	}
	s.hooks.quick.Store(int64(100 * time.Millisecond))
	hold.Store(true)
	c := rawPeer(t, s, id)
	if _, _, _, err := hello.DecodeReply(send(t, c, encodeRaw(t, topic), true)); err != nil {
		t.Fatalf("no reply after the window: %v", err)
	}
	if code := closeCodeOf(t, old, 3*time.Second); code != codeDuplicate {
		t.Fatalf("old connection closed with %d, want %d", code, codeDuplicate)
	}
	time.Sleep(300 * time.Millisecond)
	if c.Context().Err() != nil {
		t.Fatal("the new connection was closed")
	}
	if p := w.peer(id.PublicKey()); p == nil || p.Conn().Context().Err() != nil {
		t.Fatal("no live peer for the key")
	}
}

// TestKnownOnlyOutbound: holding an inbound slot does not make a key known.
func TestKnownOnlyOutbound(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, &Config{MaxHandshakes: 4, MaxHandshakesPerIP: 4}, topic)
	in, out := key(ident(t).PublicKey()), key(ident(t).PublicKey())
	s.slots[in] = &slot{inbound: true}
	s.slots[out] = &slot{}
	if tk, _, _ := s.reserveHello(in, "a", true, false); tk.class != helloStranger {
		t.Fatalf("inbound slot holder is class %d, want stranger", tk.class)
	}
	if tk, _, _ := s.reserveHello(out, "b", true, false); tk.class != helloKnown {
		t.Fatalf("outbound slot holder is class %d, want known", tk.class)
	}
}

// TestWindowFiredBeforeAdmit: a hello read just as its window ended is refused, not admitted.
func TestWindowFiredBeforeAdmit(t *testing.T) {
	checkGoroutines(t)
	s, w, topic := helloSwarm(t, nil)
	s.hooks.quick.Store(int64(200 * time.Millisecond))
	s.hooks.afterHello = func() { time.Sleep(400 * time.Millisecond) }
	c := rawPeer(t, s, sides(t, s, true))
	send(t, c, encodeRaw(t, topic), false)
	if code := closeCodeOf(t, c, 3*time.Second); code != codeProtocol {
		t.Fatalf("closed with %d, want %d", code, codeProtocol)
	}
	// The same on the other side: a reply read just as its window ended.
	c2 := rawPeer(t, s, sides(t, s, false))
	answer(t, c2, replyRaw(t, 1, topic))
	if code := closeCodeOf(t, c2, 3*time.Second); code != codeProtocol {
		t.Fatalf("follower closed with %d, want %d", code, codeProtocol)
	}
	if w.kinds(Connected) != 0 {
		t.Fatal("a hello past its window admitted")
	}
}
