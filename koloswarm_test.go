package koloswarm

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

var _ Conn = (*kolosecure.Conn)(nil)

func TestJoinConnect(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	a, b := newSwarm(t, srv, nil, nil), newSwarm(t, srv, nil, nil)
	wa, wb := watch(t, a), watch(t, b)
	topic := topicOf("join")
	join(t, a, topic, nil)
	join(t, b, topic, nil)
	waitFor(t, 15*time.Second, "both connected", func() bool {
		return wa.peer(b.PublicKey()) != nil && wb.peer(a.PublicKey()) != nil
	})
	pa, pb := wa.peer(b.PublicKey()), wb.peer(a.PublicKey())
	if !pa.Direct() || !pb.Direct() {
		t.Fatal("kolo-dht connection not reported as direct")
	}
	if !bytes.Equal(pa.PublicKey(), b.PublicKey()) || pa.Addr() != addrOf(b.Addr()) {
		t.Fatalf("peer key or address wrong: %v", pa.Addr())
	}
	if got := pa.Topics(); len(got) != 1 || got[0] != topic {
		t.Fatalf("Topics = %x", got)
	}
	echoOver(t, pa.Conn(), pb.Conn())
	if wa.kinds(Found) == 0 && wb.kinds(Found) == 0 {
		t.Fatal("no Found event on either side")
	}
}

// TestSimultaneousOpen makes both sides dial each other at the same moment and checks that they settle on one connection.
func TestSimultaneousOpen(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	srv := newServer(t)
	for round := range 8 {
		topic := topicOf(fmt.Sprint("simultaneous ", round))
		cfg := fastConfig()
		cfg.LookupInterval = time.Hour
		a, b := newSwarm(t, srv, nil, cfg), newSwarm(t, srv, nil, cfg)
		join(t, a, topic, &JoinOptions{Announce: true})
		join(t, b, topic, &JoinOptions{Announce: true})
		wa, wb := watch(t, a), watch(t, b)
		ctx := testCtx(t, 10*time.Second)
		ra, err := a.node.Lookup(ctx, topic)
		if err != nil {
			t.Fatal(err)
		}
		rb, err := b.node.Lookup(ctx, topic)
		if err != nil {
			t.Fatal(err)
		}
		var start sync.WaitGroup
		start.Add(2)
		for _, x := range []struct {
			s    *Swarm
			recs []kolodht.Record
		}{{a, ra}, {b, rb}} {
			go func() {
				defer start.Done()
				x.s.mu.Lock()
				ts := x.s.topics[topic]
				x.s.mu.Unlock()
				x.s.found(topic, ts, x.recs)
			}()
		}
		start.Wait()
		t.Cleanup(func() {
			if t.Failed() {
				wa.dump(t, "a")
				wb.dump(t, "b")
			}
		})
		stable(t, 15*time.Second, 700*time.Millisecond, "one shared connection", func() bool {
			pa, pb := wa.peer(b.PublicKey()), wb.peer(a.PublicKey())
			if pa == nil || pb == nil || pa.Conn().Context().Err() != nil || pb.Conn().Context().Err() != nil {
				return false
			}
			na, _ := a.slotCounts()
			nb, _ := b.slotCounts()
			return na == 1 && nb == 1
		})
		echoOver(t, wa.peer(b.PublicKey()).Conn(), wb.peer(a.PublicKey()).Conn())
		t.Logf("round %d: %d and %d Connected events", round, wa.kinds(Connected), wb.kinds(Connected))
		a.Close()
		b.Close()
	}
}

// TestRestartedPeer replaces a connection by a newer one from the same key at once, whichever side arbitrates.
func TestRestartedPeer(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	for _, hubSmall := range []bool{true, false} {
		small, large := identPair(t)
		hubID, peerID := small, large
		if !hubSmall {
			hubID, peerID = large, small
		}
		topic := topicOf("restart")
		hub := newSwarm(t, srv, hubID, nil)
		old := newSwarm(t, srv, peerID, nil)
		wh, wo := watch(t, hub), watch(t, old)
		join(t, hub, topic, &JoinOptions{Announce: true})
		join(t, old, topic, &JoinOptions{Lookup: true})
		waitFor(t, 15*time.Second, "first connection", func() bool { return wh.peer(peerID.PublicKey()) != nil })
		first := wh.peer(peerID.PublicKey())

		again := newSwarm(t, srv, peerID, nil)
		wa := watch(t, again)
		join(t, again, topic, &JoinOptions{Lookup: true})
		waitFor(t, 4*time.Second, "replacement", func() bool {
			p := wh.peer(peerID.PublicKey())
			return p != nil && p != first && p.Addr() == addrOf(again.Addr()) && wa.peer(hubID.PublicKey()) != nil
		})
		if code := closeCodeOf(t, wo.connOf(hubID.PublicKey(), first), 4*time.Second); code != codeDuplicate {
			t.Fatalf("old connection closed with %d, want %d", code, codeDuplicate)
		}
		hub.Close()
		old.Close()
		again.Close()
	}
}

// connOf returns the connection of the first Connected event for key, or the hub-side peer's connection if never seen.
func (w *watcher) connOf(key []byte, fallback *Peer) Conn {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.events {
		if e.Kind == Connected && bytes.Equal(e.PublicKey, key) {
			return e.Peer.Conn()
		}
	}
	return fallback.Conn()
}

// sampleSlots records the most slots and inbound slots s ever held while the test runs.
func sampleSlots(t *testing.T, s *Swarm) func() (int, int) {
	var most, mostIn atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			n, in := s.slotCounts()
			if int64(n) > most.Load() {
				most.Store(int64(n))
			}
			if int64(in) > mostIn.Load() {
				mostIn.Store(int64(in))
			}
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})
	return func() (int, int) { return int(most.Load()), int(mostIn.Load()) }
}

func TestMaxInbound(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("inbound")
	cfg := fastConfig()
	cfg.MaxPeers, cfg.MaxInbound = 3, 2
	hub := newSwarm(t, srv, nil, cfg)
	wh := watch(t, hub)
	most := sampleSlots(t, hub)
	join(t, hub, topic, &JoinOptions{Announce: true})
	for range 5 {
		join(t, newSwarm(t, srv, nil, nil), topic, &JoinOptions{Lookup: true})
	}
	stable(t, 20*time.Second, 1500*time.Millisecond, "two inbound peers", func() bool { return wh.count() == 2 })
	if n, in := most(); n > 2 || in > 2 || wh.maxPeers() > 2 {
		t.Fatalf("hub held %d slots, %d inbound, %d peers; MaxInbound is 2", n, in, wh.maxPeers())
	}
}

func TestMaxPeersOutbound(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("outbound")
	cfg := fastConfig()
	cfg.MaxPeers, cfg.MaxConnecting = 2, 4
	hub := newSwarm(t, srv, nil, cfg)
	wh := watch(t, hub)
	most := sampleSlots(t, hub)
	other := topicOf("outbound other")
	var spokes []*watcher
	for i := range 6 {
		s := newSwarm(t, srv, nil, nil)
		spokes = append(spokes, watch(t, s))
		join(t, s, []Topic{topic, other}[i%2], &JoinOptions{Announce: true})
	}
	// Each topic alone allows 2; the swarm's MaxPeers must still cap both together.
	join(t, hub, topic, &JoinOptions{Lookup: true})
	join(t, hub, other, &JoinOptions{Lookup: true})
	stable(t, 20*time.Second, 1500*time.Millisecond, "two outbound peers", func() bool { return wh.count() == 2 })
	if n, _ := most(); n > 2 || wh.maxPeers() > 2 {
		t.Fatalf("hub held %d slots and %d peers; MaxPeers is 2", n, wh.maxPeers())
	}
	total := 0
	for _, w := range spokes {
		total += w.count()
	}
	if total != 2 {
		t.Fatalf("spokes hold %d connections, want 2", total)
	}
}

func TestMaxPeersMixed(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("mixed")
	cfg := fastConfig()
	cfg.MaxPeers, cfg.MaxInbound = 3, 1
	hub := newSwarm(t, srv, nil, cfg)
	wh := watch(t, hub)
	most := sampleSlots(t, hub)
	join(t, hub, topic, nil)
	for i := range 6 {
		opts := &JoinOptions{Announce: true}
		if i%2 == 0 {
			opts = &JoinOptions{Lookup: true}
		}
		join(t, newSwarm(t, srv, nil, nil), topic, opts)
	}
	stable(t, 20*time.Second, 1500*time.Millisecond, "three peers", func() bool { return wh.count() == 3 })
	if n, in := most(); n > 3 || in > 1 {
		t.Fatalf("hub held %d slots, %d inbound; limits are 3 and 1", n, in)
	}
}

func TestTopicLimit(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	limited, open := topicOf("limited"), topicOf("open")
	hub := newSwarm(t, srv, nil, nil)
	wh := watch(t, hub)
	for range 3 {
		s := newSwarm(t, srv, nil, nil)
		join(t, s, limited, &JoinOptions{Announce: true})
	}
	o := newSwarm(t, srv, nil, nil)
	join(t, o, open, &JoinOptions{Announce: true})
	join(t, hub, limited, &JoinOptions{Lookup: true, MaxPeers: 1})
	join(t, hub, open, &JoinOptions{Lookup: true})
	stable(t, 20*time.Second, 2*time.Second, "one peer per topic", func() bool {
		return wh.count() == 2 && wh.peer(o.PublicKey()) != nil
	})
}

func TestAllow(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("allow")
	banned := ident(t)
	var mu sync.Mutex
	var seen []netip.AddrPort
	cfg := fastConfig()
	cfg.Allow = func(key ed25519.PublicKey, addr netip.AddrPort) bool {
		if bytes.Equal(key, banned.PublicKey()) {
			mu.Lock()
			seen = append(seen, addr)
			mu.Unlock()
			return false
		}
		return true
	}
	hub := newSwarm(t, srv, nil, cfg)
	wh := watch(t, hub)
	join(t, hub, topic, nil)

	b := newSwarm(t, srv, banned, nil)
	wb := watch(t, b)
	join(t, b, topic, nil)
	friend := newSwarm(t, srv, nil, nil)
	join(t, friend, topic, &JoinOptions{Announce: true})

	waitFor(t, 15*time.Second, "friend connected", func() bool { return wh.peer(friend.PublicKey()) != nil })
	waitFor(t, 10*time.Second, "Allow asked about the banned key", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(seen) >= 2
	})
	time.Sleep(time.Second)
	if wh.peer(banned.PublicKey()) != nil || wb.connOfKey(hub.PublicKey()) {
		t.Fatal("banned key connected")
	}
	mu.Lock()
	for _, a := range seen {
		if !a.Addr().IsLoopback() || a.Port() != addrOf(b.Addr()).Port() {
			t.Errorf("Allow got address %v, want the banned swarm's %v", a, b.Addr())
		}
	}
	mu.Unlock()
}

func TestAllowPanicRefuses(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("panic")
	cfg := fastConfig()
	var calls atomic.Int64
	cfg.Allow = func(ed25519.PublicKey, netip.AddrPort) bool {
		calls.Add(1)
		panic("app bug")
	}
	p := newSwarm(t, srv, nil, cfg)
	wp := watch(t, p)
	join(t, p, topic, nil)
	q := newSwarm(t, srv, nil, nil)
	wq := watch(t, q)
	join(t, q, topic, nil)
	waitFor(t, 15*time.Second, "Allow called both ways", func() bool { return calls.Load() >= 2 })
	time.Sleep(time.Second)
	if wp.kinds(Connected) != 0 || wq.kinds(Connected) != 0 {
		t.Fatal("a panicking Allow let a peer in")
	}
}

// TestRetryBackoff counts how often a refused peer dials again.
func TestRetryBackoff(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("backoff")
	p := ident(t)
	var mu sync.Mutex
	var at []time.Time
	qcfg := fastConfig()
	qcfg.Allow = func(key ed25519.PublicKey, _ netip.AddrPort) bool {
		if bytes.Equal(key, p.PublicKey()) {
			mu.Lock()
			at = append(at, time.Now())
			mu.Unlock()
			return false
		}
		return true
	}
	q := newSwarm(t, srv, nil, qcfg)
	join(t, q, topic, &JoinOptions{Announce: true})
	pcfg := fastConfig()
	pcfg.RetryMin, pcfg.RetryMax = 100*time.Millisecond, 800*time.Millisecond
	ps := newSwarm(t, srv, p, pcfg)
	join(t, ps, topic, &JoinOptions{Lookup: true})
	time.Sleep(5 * time.Second)
	ps.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(at) < 4 {
		t.Fatalf("%d attempts in 5s, want at least 4", len(at))
	}
	// Without backoff a dial and a refusal take a few milliseconds; the cap keeps attempts near one per 450ms.
	if len(at) > 25 {
		t.Fatalf("%d attempts in 5s: backoff not applied", len(at))
	}
	gaps := map[time.Duration]bool{}
	for i := 1; i < len(at); i++ {
		g := at[i].Sub(at[i-1])
		if g < 90*time.Millisecond {
			t.Fatalf("attempt %d came %v after the previous one, under RetryMin", i, g)
		}
		gaps[g.Round(10*time.Millisecond)] = true
	}
	if len(gaps) < 2 {
		t.Fatal("every gap equal: no jitter")
	}
}

func TestLeave(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	t1, t2 := topicOf("leave one"), topicOf("leave two")
	a, b := newSwarm(t, srv, nil, nil), newSwarm(t, srv, nil, nil)
	wa, wb := watch(t, a), watch(t, b)
	for _, s := range []*Swarm{a, b} {
		join(t, s, t1, nil)
		join(t, s, t2, nil)
	}
	waitFor(t, 15*time.Second, "both topics on the peer", func() bool {
		p := wa.peer(b.PublicKey())
		return p != nil && len(p.Topics()) == 2
	})
	p := wa.peer(b.PublicKey())
	a.Leave(t1)
	a.Leave(t1)
	if got := p.Topics(); len(got) != 1 || got[0] != t2 {
		t.Fatalf("after Leave(t1) Topics = %x", got)
	}
	time.Sleep(300 * time.Millisecond)
	if p.Conn().Context().Err() != nil {
		t.Fatal("peer closed though it shares t2")
	}
	a.Leave(t2)
	waitFor(t, 5*time.Second, "peer lost on both sides", func() bool {
		return wa.peer(b.PublicKey()) == nil && wb.peer(a.PublicKey()) == nil
	})
	if code := closeCodeOf(t, wb.connOf(a.PublicKey(), nil), time.Second); code != codeNormal {
		t.Fatalf("closed with %d, want %d", code, codeNormal)
	}
	join(t, a, t2, nil)
	waitFor(t, 15*time.Second, "reconnected after rejoining", func() bool { return wa.peer(b.PublicKey()) != nil })
}

func TestUnreachableEvent(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("unreachable")
	gone := newSwarm(t, srv, nil, nil)
	join(t, gone, topic, &JoinOptions{Announce: true})
	key := gone.PublicKey()
	gone.Close()
	a := newSwarm(t, srv, nil, nil)
	wa := watch(t, a)
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitFor(t, 15*time.Second, "Unreachable", func() bool { return wa.kinds(Unreachable) > 0 })
	wa.mu.Lock()
	defer wa.mu.Unlock()
	for _, e := range wa.events {
		if e.Kind == Unreachable {
			if !bytes.Equal(e.PublicKey, key) || e.Topic != topic || !errors.Is(e.Err, kolodht.ErrUnreachable) {
				t.Fatalf("Unreachable event %+v", e)
			}
		}
	}
}

func (w *watcher) connOfKey(key []byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.events {
		if e.Kind == Connected && bytes.Equal(e.PublicKey, key) {
			return true
		}
	}
	return false
}
