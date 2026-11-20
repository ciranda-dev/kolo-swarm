package koloswarm

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	"github.com/ciranda-dev/kolo-swarm/internal/hello"
)

// rawNode is a kolo-dht node without a swarm that announces topic and hands every inbound connection to handle.
type rawNode struct {
	node *kolodht.Node
	id   *koloid.Identity
	mu   sync.Mutex
	at   []time.Time
}

func newRawNode(t *testing.T, srv *kolodht.Node, id *koloid.Identity, topic Topic, handle func(*kolosecure.Conn)) *rawNode {
	t.Helper()
	if id == nil {
		id = ident(t)
	}
	n, err := kolodht.New(context.Background(), "127.0.0.1:0", id, fastConfig().DHT)
	if err != nil {
		t.Fatal(err)
	}
	r := &rawNode{node: n, id: id}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		n.Close()
		<-done
	})
	bctx := testCtx(t, 10*time.Second)
	if err := n.Bootstrap(bctx, []netip.AddrPort{addrOf(srv.Addr())}); err != nil {
		t.Fatal(err)
	}
	if err := n.Announce(bctx, topic); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			c, err := n.Accept(ctx)
			if err != nil {
				return
			}
			r.mu.Lock()
			r.at = append(r.at, time.Now())
			r.mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				handle(c)
			}()
		}
	}()
	return r
}

func (r *rawNode) accepts() []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Time(nil), r.at...)
}

// actHello completes the swarm hello on c for topic, from whichever side the keys give the raw node.
func actHello(c *kolosecure.Conn, swarmKey ed25519.PublicKey, rawKey ed25519.PublicKey, topic Topic, gen uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if string(rawKey) > string(swarmKey) {
		st, err := c.OpenStream(ctx)
		if err != nil {
			return err
		}
		b, _ := hello.Encode([][32]byte{topic})
		st.Write(b)
		st.Close()
		st.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = readMsg(st)
		return err
	}
	st, err := c.AcceptStream(ctx)
	if err != nil {
		return err
	}
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := readMsg(st); err != nil {
		return err
	}
	b, _ := hello.EncodeReply(1, gen, [][32]byte{topic})
	st.Write(b)
	return st.Close()
}

// TestDuplicateCloseBackoff: a peer that closes every connection with code 2 is dialed with growing delays.
func TestDuplicateCloseBackoff(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	srv := newServer(t)
	cfg := fastConfig()
	cfg.RetryMin, cfg.RetryMax = 500*time.Millisecond, 10*time.Second

	t.Run("before admission", func(t *testing.T) {
		topic := topicOf("dup before")
		atk := newRawNode(t, srv, nil, topic, func(c *kolosecure.Conn) { c.CloseWithError(codeDuplicate, "") })
		s := newSwarm(t, srv, nil, cfg)
		join(t, s, topic, &JoinOptions{Lookup: true})
		time.Sleep(3 * time.Second)
		if n := len(atk.accepts()); n == 0 || n > 8 {
			t.Fatalf("%d connections in 3s, want 1 to 8", n)
		}
	})

	t.Run("after admission", func(t *testing.T) {
		topic := topicOf("dup after")
		var s *Swarm
		var ready sync.WaitGroup
		ready.Add(1)
		var gen uint64
		var mu sync.Mutex
		atkID := ident(t)
		atk := newRawNode(t, srv, atkID, topic, func(c *kolosecure.Conn) {
			ready.Wait()
			mu.Lock()
			gen++
			g := gen
			mu.Unlock()
			if actHello(c, s.PublicKey(), atkID.PublicKey(), topic, g) == nil {
				time.Sleep(50 * time.Millisecond)
			}
			c.CloseWithError(codeDuplicate, "")
		})
		s = newSwarm(t, srv, nil, cfg)
		ready.Done()
		w := watch(t, s)
		join(t, s, topic, &JoinOptions{Lookup: true})
		time.Sleep(6 * time.Second)
		at := atk.accepts()
		if w.kinds(Connected) == 0 {
			t.Fatal("the attacker was never admitted")
		}
		if len(at) > 9 {
			t.Fatalf("%d connections in 6s: no backoff", len(at))
		}
		var most time.Duration
		for i := 1; i < len(at); i++ {
			most = max(most, at[i].Sub(at[i-1]))
		}
		if most < 1200*time.Millisecond && len(at) > 5 {
			t.Fatalf("longest gap %v over %d attempts: delays do not grow past 2 × RetryMin", most, len(at))
		}
	})
}

// TestInboundCannotEclipseTopic: inbound peers that claim a topic take at most its inbound share.
func TestInboundCannotEclipseTopic(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("eclipse")
	hub := newSwarm(t, srv, nil, nil)
	wh := watch(t, hub)
	join(t, hub, topic, &JoinOptions{Announce: true, Lookup: true, MaxPeers: 2})
	for range 2 {
		c := rawPeer(t, hub, sides(t, hub, true))
		send(t, c, encodeRaw(t, topic), true)
	}
	waitFor(t, 3*time.Second, "one inbound claim admitted", func() bool { return wh.count() == 1 })
	honest := newSwarm(t, srv, nil, nil)
	join(t, honest, topic, &JoinOptions{Announce: true})
	waitFor(t, 6*time.Second, "the honest peer", func() bool { return wh.peer(honest.PublicKey()) != nil })
	if wh.count() > 2 {
		t.Fatalf("%d peers on a topic of 2", wh.count())
	}
	if n, in := hub.slotCounts(); n != 2 || in != 1 {
		t.Fatalf("hub holds %d peers, %d inbound; want 2 and 1", n, in)
	}
}

func TestStrangerHelloReserve(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, &Config{MaxHandshakes: 4, MaxHandshakesPerIP: 4}, topic)
	src := func(i int) string { return "ip 198.51.100." + string(rune('0'+i)) }
	for i := range 2 {
		if _, _, ok := s.reserveHello(key(ident(t).PublicKey()), src(i), true, false); !ok {
			t.Fatalf("stranger %d refused", i)
		}
	}
	if _, code, ok := s.reserveHello(key(ident(t).PublicKey()), src(9), true, false); ok || code != codeFull {
		t.Fatal("a third stranger took a reserved hello")
	}
	// A lookup candidate alone is a stranger; a key that connected before is known.
	cand1 := key(ident(t).PublicKey())
	s.cands[cand1] = &cand{topics: map[Topic]bool{topic: true}}
	if _, _, ok := s.reserveHello(cand1, src(3), true, false); ok {
		t.Fatal("a mere candidate took the known-key reserve")
	}
	known := key(ident(t).PublicKey())
	s.cands[known] = &cand{topics: map[Topic]bool{topic: true}, history: history{connected: true}}
	if _, _, ok := s.reserveHello(known, src(4), true, false); !ok {
		t.Fatal("a key that connected before found no reserved hello")
	}
	if _, _, ok := s.reserveHello(key(ident(t).PublicKey()), "none", false, true); !ok {
		t.Fatal("Attach found no reserved hello")
	}
	if _, _, ok := s.reserveHello(key(ident(t).PublicKey()), "none", false, true); ok {
		t.Fatal("MaxHandshakes exceeded")
	}

	// Attach cannot take the known-key reserve.
	s3 := unitSwarm(t, &Config{MaxHandshakes: 4, MaxHandshakesPerIP: 4}, topic)
	for i := range 2 {
		s3.reserveHello(key(ident(t).PublicKey()), src(i), true, false)
	}
	if _, _, ok := s3.reserveHello(key(ident(t).PublicKey()), "none", false, true); !ok {
		t.Fatal("first Attach refused")
	}
	if _, _, ok := s3.reserveHello(key(ident(t).PublicKey()), "relay x", false, true); ok {
		t.Fatal("a second Attach took the known-key reserve")
	}
	k3 := key(ident(t).PublicKey())
	s3.slots[k3] = &slot{}
	if _, _, ok := s3.reserveHello(k3, src(5), true, false); !ok {
		t.Fatal("a known key found no reserved hello")
	}

	// Known keys cannot take the Attach reserve, nor Attach the known one.
	s2 := unitSwarm(t, &Config{MaxHandshakes: 4, MaxHandshakesPerIP: 4}, topic)
	for i := range 3 {
		k := key(ident(t).PublicKey())
		s2.slots[k] = &slot{}
		if _, _, ok := s2.reserveHello(k, src(i), true, false); !ok {
			t.Fatalf("known key %d refused", i)
		}
	}
	tk, _, ok := s2.reserveHello(key(ident(t).PublicKey()), "none", false, true)
	if !ok {
		t.Fatal("Attach found no reserved hello next to known keys")
	}
	s2.releaseHello(tk)
	if s2.hellos != 3 || s2.attaching != 0 || len(s2.helloSrc) != 3 {
		t.Fatalf("after release: %d hellos, %d attaching, %d sources", s2.hellos, s2.attaching, len(s2.helloSrc))
	}
}

// relayConn is a test double for a relayed Conn that names its relay.
type relayConn struct {
	*fake
	relay ed25519.PublicKey
}

func (r relayConn) RelayPublicKey() ed25519.PublicKey { return r.relay }

func TestSourceBuckets(t *testing.T) {
	r1, r2 := ident(t).PublicKey(), ident(t).PublicKey()
	f := newFake(ident(t).PublicKey())
	a, b, c := sourceOf(relayConn{f, r1}), sourceOf(relayConn{f, r2}), sourceOf(f)
	if a == b || a == c || b == c || c != "none" {
		t.Fatalf("buckets %q %q %q", a, b, c)
	}
	if ip := sourceOf(remoteConn{f, &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 9}}); ip != "ip 203.0.113.7" {
		t.Fatalf("IPv4 bucket %q", ip)
	}
	topic := topicOf("unit")
	s := unitSwarm(t, &Config{MaxHandshakes: 16, MaxHandshakesPerIP: 2}, topic)
	for range 2 {
		if _, _, ok := s.reserveHello(key(ident(t).PublicKey()), a, false, true); !ok {
			t.Fatal("relay bucket refused under its cap")
		}
	}
	if _, _, ok := s.reserveHello(key(ident(t).PublicKey()), a, false, true); ok {
		t.Fatal("third hello through one relay accepted")
	}
	if _, _, ok := s.reserveHello(key(ident(t).PublicKey()), b, false, true); !ok {
		t.Fatal("another relay shares the first one's bucket")
	}
}

func TestHelloPerIP(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxHandshakesPerIP = 2
	cfg.HelloTimeout = 30 * time.Second
	s, _, _ := helloSwarm(t, cfg)
	s.hooks.quick.Store(int64(30 * time.Second))
	rawPeer(t, s, ident(t))
	rawPeer(t, s, ident(t))
	waitFor(t, 5*time.Second, "two hellos in progress", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.hellos == 2
	})
	c := rawPeer(t, s, ident(t))
	if code := closeCodeOf(t, c, 5*time.Second); code != codeFull {
		t.Fatalf("third hello from one address closed with %d, want %d", code, codeFull)
	}
}

func TestSilentStrangers(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("silent")
	cfg := fastConfig()
	cfg.MaxHandshakes, cfg.MaxHandshakesPerIP, cfg.HelloTimeout = 4, 4, 30*time.Second
	hubID := ident(t)
	hub := newSwarm(t, srv, hubID, cfg)
	hub.hooks.quick.Store(int64(30 * time.Second))
	wh := watch(t, hub)
	join(t, hub, topic, nil)
	for range 2 {
		rawPeer(t, hub, ident(t))
	}
	waitFor(t, 5*time.Second, "two silent hellos", func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return hub.hellos == 2
	})
	third := rawPeer(t, hub, ident(t))
	if code := closeCodeOf(t, third, 5*time.Second); code != codeFull {
		t.Fatalf("third silent stranger closed with %d, want %d", code, codeFull)
	}
	// Attach still gets its reserved hello.
	bID := ident(t)
	b := newSwarm(t, srv, bID, nil)
	join(t, b, topic, &JoinOptions{Lookup: true})
	ca, cb := securePair(t, hubID, bID)
	if ea, eb := attachBoth(t, hub, b, relayed{ca}, relayed{cb}); ea != nil && !errors.Is(ea, ErrDuplicate) || eb != nil && !errors.Is(eb, ErrDuplicate) {
		t.Fatalf("Attach with strangers holding hellos: %v, %v", ea, eb)
	}
	waitFor(t, 5*time.Second, "b connected", func() bool { return wh.peer(bID.PublicKey()) != nil })
}

// stall opens or accepts the hello stream on c, writes b, and then sends nothing more.
func stall(t *testing.T, c *kolosecure.Conn, open bool, b []byte) {
	t.Helper()
	ctx := testCtx(t, 5*time.Second)
	var st interface{ Write([]byte) (int, error) }
	if open {
		s, err := c.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		st = s
	} else {
		s, err := c.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		st = s
	}
	if len(b) > 0 {
		st.Write(b)
	}
}

func TestFirstByteTimeout(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.HelloTimeout = 10 * time.Second
	s, _, _ := helloSwarm(t, cfg)
	for _, larger := range []bool{true, false} {
		for _, payload := range [][]byte{nil, {0x00}} {
			c := rawPeer(t, s, sides(t, s, larger))
			start := time.Now()
			if payload != nil {
				stall(t, c, larger, payload)
			}
			if code := closeCodeOf(t, c, 5*time.Second); code != codeProtocol {
				t.Fatalf("peer that stalls after %d bytes closed with %d", len(payload), code)
			}
			if d := time.Since(start); d < 1500*time.Millisecond || d > 3500*time.Millisecond {
				t.Fatalf("peer that stalls after %d bytes closed after %v, want about 2s", len(payload), d)
			}
		}
	}
}

// TestHelloQuickWindow: peers found by lookups that send one byte and stall are closed by about 2s, and Attach works.
func TestHelloQuickWindow(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("quick")
	cfg := fastConfig()
	cfg.MaxHandshakes, cfg.MaxHandshakesPerIP, cfg.HelloTimeout = 4, 4, 10*time.Second
	hubID := ident(t)
	hub := newSwarm(t, srv, hubID, cfg)
	wh := watch(t, hub)
	join(t, hub, topic, &JoinOptions{Announce: true})
	var ids []*koloid.Identity
	var recs []kolodht.Record
	for range 4 {
		id := sides(t, hub, true)
		ids = append(ids, id)
		recs = append(recs, kolodht.Record{Topic: topic, PublicKey: id.PublicKey(), Addr: fakeAddr()})
	}
	hub.mu.Lock()
	ts := hub.topics[topic]
	hub.mu.Unlock()
	hub.found(topic, ts, recs)
	start := time.Now()
	var conns []*kolosecure.Conn
	for _, id := range ids {
		c := rawPeer(t, hub, id)
		if c.Context().Err() == nil {
			ctx := testCtx(t, 2*time.Second)
			if st, err := c.OpenStream(ctx); err == nil {
				st.Write([]byte{0x00})
			}
		}
		conns = append(conns, c)
	}
	for i, c := range conns {
		select {
		case <-c.Context().Done():
		case <-time.After(time.Until(start.Add(3500 * time.Millisecond))):
			t.Fatalf("stalled peer %d still open after %v", i, time.Since(start))
		}
	}
	bID := ident(t)
	b := newSwarm(t, srv, bID, nil)
	join(t, b, topic, &JoinOptions{Lookup: true})
	ca, cb := securePair(t, hubID, bID)
	if ea, eb := attachBoth(t, hub, b, relayed{ca}, relayed{cb}); ea != nil && !errors.Is(ea, ErrDuplicate) || eb != nil && !errors.Is(eb, ErrDuplicate) {
		t.Fatalf("Attach: %v, %v", ea, eb)
	}
	waitFor(t, 5*time.Second, "b connected", func() bool { return wh.peer(bID.PublicKey()) != nil })
}

func TestCandidateQuota(t *testing.T) {
	a, b := topicOf("A"), topicOf("B")
	s := unitSwarm(t, &Config{MaxCandidates: 16}, a)
	s.topics[b] = &topicState{opts: JoinOptions{Lookup: true, MaxPeers: 8}, ctx: s.ctx, cancel: func() {}}
	var recs []kolodht.Record
	for range 16 {
		recs = append(recs, kolodht.Record{Topic: a, PublicKey: ident(t).PublicKey(), Addr: fakeAddr()})
	}
	s.found(a, s.topics[a], recs)
	if n := len(s.cands); n != 8 {
		t.Fatalf("topic A holds %d of 16 candidates, want its share of 8", n)
	}
	bkey := ident(t).PublicKey()
	s.found(b, s.topics[b], []kolodht.Record{{Topic: b, PublicKey: bkey, Addr: netip.MustParseAddrPort("127.0.0.1:10")}})
	if c := s.cands[key(bkey)]; c == nil || !c.topics[b] {
		t.Fatal("topic B's candidate dropped")
	}
}

func TestUnreachableBudget(t *testing.T) {
	a, b := topicOf("A"), topicOf("B")
	s := unitSwarm(t, &Config{MaxEvents: 16, MaxCandidates: 64}, a)
	var recs []kolodht.Record
	for range 20 {
		recs = append(recs, kolodht.Record{Topic: a, PublicKey: ident(t).PublicKey(), Addr: fakeAddr()})
	}
	s.found(a, s.topics[a], recs)
	if n := s.events.Len(); n != 16 {
		t.Fatalf("%d Found queued, want 16", n)
	}
	s.unreachable(b, kolodht.Record{Topic: b, PublicKey: ident(t).PublicKey(), Addr: netip.MustParseAddrPort("127.0.0.1:10")})
	if n := s.events.Len(); n != 17 {
		t.Fatal("Unreachable dropped because Found filled the queue")
	}
}

func TestAdmitLeftTopic(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, nil, topic)
	s.topics[topic].left = true
	k := key(ident(t).PublicKey())
	f := newFake(k[:])
	if _, code, err := s.admit(f, k, netip.AddrPort{}, true, true, []Topic{topic}, false, generation{}); !errors.Is(err, ErrRefused) || code != codeRefused {
		t.Fatalf("admit for a left topic: %d, %v", code, err)
	}
	s.slots[k] = &slot{topic: topic}
	if _, code, err := s.admit(f, k, netip.AddrPort{}, false, true, []Topic{topic}, false, generation{}); !errors.Is(err, ErrRefused) || code != codeRefused {
		t.Fatalf("admit into a dial slot of a left topic: %d, %v", code, err)
	}
}

func TestDialSlotTopicRoom(t *testing.T) {
	a, b := topicOf("A"), topicOf("B")
	s := unitSwarm(t, nil, a)
	s.topics[a].opts.MaxPeers = 1
	s.topics[b] = &topicState{opts: JoinOptions{Lookup: true, MaxPeers: 8}, ctx: s.ctx, cancel: func() {}}
	other := key(ident(t).PublicKey())
	if _, _, err := s.admit(newFake(other[:]), other, netip.AddrPort{}, false, true, []Topic{a}, false, generation{}); err != nil {
		t.Fatal(err)
	}
	k := key(ident(t).PublicKey())
	s.slots[k] = &slot{topic: b}
	p, _, err := s.admit(newFake(k[:]), k, netip.AddrPort{}, false, true, []Topic{a, b}, false, generation{})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Topics(); len(got) != 1 || got[0] != b {
		t.Fatalf("peer of a dial slot counts in %d topics; the full topic A must be left out", len(got))
	}
}

func TestLeaveCancelsDial(t *testing.T) {
	a, b := topicOf("A"), topicOf("B")
	s := unitSwarm(t, nil, a)
	s.topics[b] = &topicState{opts: JoinOptions{Lookup: true, MaxPeers: 8}, ctx: s.ctx, cancel: func() {}}
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	s.slots[key(ident(t).PublicKey())] = &slot{topic: a, dial: cancelA}
	s.slots[key(ident(t).PublicKey())] = &slot{topic: b, dial: cancelB}
	s.Leave(a)
	if ctxA.Err() == nil {
		t.Fatal("Leave did not cancel the dial for its topic")
	}
	if ctxB.Err() != nil {
		t.Fatal("Leave canceled a dial for another topic")
	}
}

// TestLeaveDuringDials: Leave cancels a dial for its topic that would otherwise wait for a server that is gone.
func TestLeaveDuringDials(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("leave busy")
	join(t, newSwarm(t, srv, nil, nil), topic, &JoinOptions{Announce: true})
	cfg := fastConfig()
	cfg.DHT.RequestTimeout = 5 * time.Second
	s := newSwarm(t, srv, nil, cfg)
	join(t, s, topic, &JoinOptions{Announce: true})
	recs, err := s.node.Lookup(testCtx(t, 10*time.Second), topic)
	if err != nil || len(recs) != 1 {
		t.Fatalf("Lookup: %d records, %v", len(recs), err)
	}
	srv.Close()
	s.mu.Lock()
	ts := s.topics[topic]
	s.mu.Unlock()
	dialCtx := make(chan context.Context, 1)
	s.hooks.connect = func(ctx context.Context, rec kolodht.Record) (*kolosecure.Conn, error) {
		select {
		case dialCtx <- ctx:
		default:
		}
		return s.node.Connect(ctx, rec)
	}
	s.found(topic, ts, recs)
	var dctx context.Context
	select {
	case dctx = <-dialCtx:
	case <-time.After(5 * time.Second):
		t.Fatal("no dial started")
	}
	s.Leave(topic)
	waitFor(t, 300*time.Millisecond, "the dial canceled", func() bool { return dctx.Err() != nil })
	waitFor(t, 5*time.Second, "no slot left", func() bool { n, _ := s.slotCounts(); return n == 0 })
}

func TestFollowerKeepsHighestGeneration(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, nil, topic)
	k := key(ident(t).PublicKey())
	c1, c2 := newFake(k[:]), newFake(k[:])
	if _, _, err := s.admit(c2, k, netip.AddrPort{}, false, true, []Topic{topic}, true, generation{n: 2}); err != nil {
		t.Fatal(err)
	}
	if _, code, err := s.admit(c1, k, netip.AddrPort{}, false, true, []Topic{topic}, true, generation{n: 1}); !errors.Is(err, ErrDuplicate) || code != codeDuplicate {
		t.Fatalf("older generation admitted: %d, %v", code, err)
	}
	c1.peerClose(codeDuplicate)
	time.Sleep(50 * time.Millisecond)
	s.mu.Lock()
	kept := s.slots[k] != nil && s.slots[k].peer != nil && s.slots[k].peer.conn == c2
	s.mu.Unlock()
	if !kept || c2.ctx.Err() != nil {
		t.Fatal("the newest generation was not kept")
	}
	c3 := newFake(k[:])
	if _, _, err := s.admit(c3, k, netip.AddrPort{}, false, true, []Topic{topic}, true, generation{n: 3}); err != nil {
		t.Fatalf("newer generation refused: %v", err)
	}
	if c2.ctx.Err() == nil {
		t.Fatal("replaced connection left open")
	}
}

func TestAddressChangeKeepsFails(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, nil, topic)
	pub := ident(t).PublicKey()
	k := key(pub)
	s.found(topic, s.topics[topic], []kolodht.Record{{Topic: topic, PublicKey: pub, Addr: netip.MustParseAddrPort("127.0.0.1:9")}})
	c := s.cands[k]
	c.fails, c.next = 3, time.Now().Add(time.Hour)
	s.found(topic, s.topics[topic], []kolodht.Record{{Topic: topic, PublicKey: pub, Addr: netip.MustParseAddrPort("127.0.0.1:10")}})
	if c.fails != 3 {
		t.Fatalf("address change reset fails to %d", c.fails)
	}
	if !c.next.IsZero() {
		t.Fatal("address change kept the wait")
	}
}

// TestAllowBeforeDial: a key Allow refuses is never dialed, so its node never sees a connection.
func TestAllowBeforeDial(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("allow dial")
	banned := ident(t)
	raw := newRawNode(t, srv, banned, topic, func(c *kolosecure.Conn) { c.Close() })
	cfg := fastConfig()
	cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool { return string(k) != string(banned.PublicKey()) }
	s := newSwarm(t, srv, nil, cfg)
	w := watch(t, s)
	join(t, s, topic, &JoinOptions{Lookup: true})
	waitFor(t, 5*time.Second, "Found", func() bool { return w.kinds(Found) > 0 })
	time.Sleep(2 * time.Second)
	if n := len(raw.accepts()); n != 0 {
		t.Fatalf("the refused key received %d connections", n)
	}
}

func TestAttachAllowRefused(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	ia, ib := ident(t), ident(t)
	cfg := fastConfig()
	cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool { return string(k) != string(ib.PublicKey()) }
	a := newSwarm(t, srv, ia, cfg)
	join(t, a, topicOf("attach allow"), nil)
	ca, _ := securePair(t, ia, ib)
	if err := a.Attach(testCtx(t, 5*time.Second), relayed{ca}, true); !errors.Is(err, ErrRefused) {
		t.Fatalf("Attach of a refused key: %v", err)
	}
	waitFor(t, 2*time.Second, "refused connection closed", func() bool { return ca.Context().Err() != nil })
}
