package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	kolorelay "github.com/ciranda-dev/kolo-relay"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// relayFrames are the functions that run only with Config.Relays.
var relayFrames = []string{"kolo-swarm.(*Swarm).reserveLoop(", "kolo-swarm.(*Swarm).relayChain(", "kolo-swarm.(*Swarm).dialVia("}

func TestRelayDefaultOff(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf(t.Name())
	empty := fastConfig()
	empty.Relays = []Relay{}
	b := newSwarm(t, srv, nil, nil)
	x := newSwarm(t, srv, nil, nil)
	a := newSwarm(t, srv, nil, empty)
	if a.relays != nil || b.relays != nil {
		t.Fatal("relay state without Config.Relays")
	}
	held := make(chan struct{})
	g := newGate(a)
	g.set(x.PublicKey(), func(ctx context.Context) error {
		holdUntil(held)(ctx)
		return kolodht.ErrUnreachable
	})
	wa, wb := watch(t, a), watch(t, b)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, x, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitFor(t, 20*time.Second, "a dialing x", func() bool { n, _ := g.count(x.PublicKey()); return n > 0 })
	dialing := false
	for _, st := range goroutines() {
		dialing = dialing || strings.Contains(st, "kolo-swarm.(*Swarm).dial(")
		for _, f := range relayFrames {
			if strings.Contains(st, f) {
				t.Fatalf("relay goroutine %s without Config.Relays", f)
			}
		}
	}
	if !dialing {
		t.Fatal("no dial goroutine found: the stack check would see nothing")
	}
	close(held)
	if p := waitDirect(t, wa, b.PublicKey()); p.Addr() != addrOf(b.Addr()) {
		t.Fatalf("peer address %v", p.Addr())
	}
	waitFor(t, 20*time.Second, "Unreachable at once", func() bool { return wa.kinds(Unreachable) > 0 })
	if wa.kinds(RelayChanged)+wb.kinds(RelayChanged) != 0 {
		t.Fatal("RelayChanged without Config.Relays")
	}
}

func TestEventKindStrings(t *testing.T) {
	for k, want := range map[EventKind]string{Found: "found", Connected: "connected", Unreachable: "unreachable", Lost: "lost", RelayChanged: "relay changed", 0: "unknown"} {
		if got := k.String(); got != want {
			t.Errorf("%d: %q, want %q", k, got, want)
		}
	}
}

// relayedPair connects a (lookup only) to b (announce only) through relays, with a's direct dials to b refused.
func relayedPair(t *testing.T, topic Topic, ca, cb *Config) (a, b *Swarm, wa, wb *watcher, g *gate) {
	t.Helper()
	srv := newServer(t)
	b = newSwarm(t, srv, nil, cb)
	a = newSwarm(t, srv, nil, ca)
	g = newGate(a)
	g.set(b.PublicKey(), refuseConn)
	wa, wb = watch(t, a), watch(t, b)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	return
}

func TestRelayOneSideLooksUp(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	a, b, wa, wb, _ := relayedPair(t, topicOf(t.Name()), relayConfig(r.entry()), relayConfig(r.entry()))
	pa := waitRelayed(t, wa, b.PublicKey(), r.key)
	pb := waitRelayed(t, wb, a.PublicKey(), r.key)
	if pa.Addr().IsValid() || pb.Addr().IsValid() {
		t.Fatal("a relayed peer has an address")
	}
	echoOver(t, pa.Conn(), pb.Conn())
	if wa.kinds(RelayChanged) != 0 {
		t.Fatal("a lookup-only swarm queued RelayChanged")
	}
	if !wb.held(r.key) {
		t.Fatal("the announcing swarm holds no reservation")
	}
}

func TestRelayFallbackFirewall(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	walled := func() *Config {
		c := relayConfig(r.entry())
		c.DHT.Secure.Transport.AcceptFunc = func(netip.AddrPort) bool { return false }
		return c
	}
	a := newSwarm(t, srv, nil, walled())
	b := newSwarm(t, srv, nil, walled())
	c := newSwarm(t, srv, nil, relayConfig(r.entry()))
	wa, wb, wc := watch(t, a), watch(t, b), watch(t, c)
	join(t, a, topic, nil)
	join(t, b, topic, nil)
	// c only announces, so a and b dial it; c's own dial to a firewall would go through the relay first.
	join(t, c, topic, &JoinOptions{Announce: true})
	pa := waitRelayed(t, wa, b.PublicKey(), r.key)
	pb := waitRelayed(t, wb, a.PublicKey(), r.key)
	if _, ok := pa.Conn().(*kolorelay.Conn); !ok {
		t.Fatalf("relayed Conn is %T", pa.Conn())
	}
	echoOver(t, pa.Conn(), pb.Conn())
	echoOver(t, pb.Conn(), pa.Conn())
	waitDirect(t, wa, c.PublicKey())
	waitDirect(t, wb, c.PublicKey())
	waitDirect(t, wc, a.PublicKey())
	waitDirect(t, wc, b.PublicKey())
	for _, w := range []struct {
		w     *watcher
		other ed25519.PublicKey
	}{{wa, b.PublicKey()}, {wb, a.PublicKey()}} {
		w.w.mu.Lock()
		for _, e := range w.w.events {
			if e.Kind == Connected && bytes.Equal(e.PublicKey, w.other) && e.Peer.Direct() {
				t.Error("a direct connection through the firewall")
			}
		}
		w.w.mu.Unlock()
	}
}

func TestRelayedStreamsFollowSwarmTransport(t *testing.T) {
	r1, r2 := startRelay(t, nil), startRelay(t, nil)
	open := func(t *testing.T, c Conn, n int, d time.Duration) (int, error) {
		ctx := testCtx(t, d)
		for i := range n {
			if _, err := c.OpenStream(ctx); err != nil {
				return i, err
			}
		}
		return n, nil
	}
	for i, first := range []*testRelay{r1, r2} {
		other := []*testRelay{r2, r1}[i]
		t.Run("through "+[]string{"first", "second"}[i], func(t *testing.T) {
			checkGoroutines(t)
			cfg := func() *Config {
				c := relayConfig(first.entry(), other.entry())
				c.DHT.Secure.Transport.MaxIncomingStreams = 1000
				return c
			}
			_, b, wa, _, _ := relayedPair(t, topicOf(t.Name()), cfg(), cfg())
			p := waitRelayed(t, wa, b.PublicKey(), first.key)
			if n, err := open(t, p.Conn(), 17, 20*time.Second); err != nil {
				t.Fatalf("opened %d of 17 streams: %v", n, err)
			}
		})
	}
	t.Run("default", func(t *testing.T) {
		checkGoroutines(t)
		_, b, wa, _, _ := relayedPair(t, topicOf(t.Name()), relayConfig(r1.entry()), relayConfig(r1.entry()))
		p := waitRelayed(t, wa, b.PublicKey(), r1.key)
		n, err := open(t, p.Conn(), 17, 3*time.Second)
		if err == nil || n > 16 || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("opened %d of 17 streams with the default limit of 16: %v", n, err)
		}
	})
}

func TestRelayFirstContactSequential(t *testing.T) {
	checkGoroutines(t)
	var returned, early atomic.Bool
	var seq atomic.Int64
	var connectAt, returnedAt atomic.Int64
	started := make(chan struct{})
	var once sync.Once
	r2 := startRelay(t, &kolorelay.ServerConfig{AllowConnect: func(_, _ ed25519.PublicKey) bool {
		connectAt.CompareAndSwap(0, seq.Add(1))
		return true
	}})
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, relayConfig(r2.entry()))
	a := newSwarm(t, srv, nil, relayConfig(r2.entry()))
	g := newGate(a)
	g.set(b.PublicKey(), func(ctx context.Context) error {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
		returnedAt.Store(seq.Add(1))
		returned.Store(true)
		return kolodht.ErrUnreachable
	})
	logRelays(a, func(context.Context, ed25519.PublicKey, ed25519.PublicKey) {
		if !returned.Load() {
			early.Store(true)
		}
		once.Do(func() { close(started) })
	})
	wa := watch(t, a)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitRelayed(t, wa, b.PublicKey(), r2.key)
	if early.Load() {
		t.Fatal("the relay dial started while the first Connect was still running")
	}
	if c, ret := connectAt.Load(), returnedAt.Load(); c == 0 || c < ret {
		t.Fatalf("the relay saw the Connect at step %d, the direct Connect returned at step %d", c, ret)
	}
}

func TestRelayFirstContactAfterPunchWindow(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, relayConfig(r.entry()))
	a := newSwarm(t, srv, nil, relayConfig(r.entry()))
	a.mu.Lock()
	a.hooks.relayAfter = 300 * time.Millisecond
	a.mu.Unlock()
	// The direct Connect runs as long as one through 3 storers whose punches start but never connect.
	release := make(chan struct{})
	newGate(a).set(b.PublicKey(), func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-time.After(30 * time.Second):
			return kolodht.ErrUnreachable
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	wa, wb := watch(t, a), watch(t, b)
	join(t, b, topic, &JoinOptions{Announce: true})
	start := time.Now()
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitRelayed(t, wa, b.PublicKey(), r.key)
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("relayed %v after the first Connect started, which still ran", d.Round(time.Millisecond))
	}
	close(release)
	waitDirect(t, wa, b.PublicKey())
	waitDirect(t, wb, a.PublicKey())
}

func TestRelayNotTriedWithinPunchWindow(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, relayConfig(r.entry()))
	a := newSwarm(t, srv, nil, relayConfig(r.entry()))
	a.mu.Lock()
	a.hooks.relayAfter = time.Second
	a.mu.Unlock()
	log := logRelays(a, nil)
	wa := watch(t, a)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitDirect(t, wa, b.PublicKey())
	time.Sleep(2 * time.Second)
	if n := log.count(); n != 0 {
		t.Fatalf("%d relay dials for a key whose direct Connect connected within the punch window", n)
	}
}

func TestRelayInboundRelayedSkipsChain(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	a := newSwarm(t, srv, nil, relayConfig(r.entry()))
	b := newSwarm(t, srv, nil, relayConfig(r.entry()))
	a.mu.Lock()
	a.hooks.relayAfter = 2 * time.Second
	a.mu.Unlock()
	release, dialing := make(chan struct{}), make(chan struct{})
	var once sync.Once
	newGate(a).set(b.PublicKey(), func(ctx context.Context) error {
		once.Do(func() { close(dialing) })
		return holdUntil(release)(ctx)
	})
	newGate(b).set(a.PublicKey(), func(ctx context.Context) error {
		holdUntil(dialing)(ctx)
		return kolodht.ErrUnreachable
	})
	log := logRelays(a, nil)
	wa, wb := watch(t, a), watch(t, b)
	join(t, a, topic, nil)
	join(t, b, topic, nil)
	waitRelayed(t, wa, b.PublicKey(), r.key)
	time.Sleep(3 * time.Second)
	if n := len(log.to(b.PublicKey())); n != 0 {
		t.Fatalf("a dialed b through the relay %d times while it held b's relayed connection", n)
	}
	close(release)
	waitDirect(t, wa, b.PublicKey())
	waitDirect(t, wb, a.PublicKey())
}

func TestRelayAfterPunchWindow(t *testing.T) {
	for _, c := range []struct {
		rt, want time.Duration
	}{{0, 12 * time.Second}, {300 * time.Millisecond, 10600 * time.Millisecond}, {2 * time.Second, 14 * time.Second}} {
		cfg := fastConfig()
		cfg.DHT.RequestTimeout = c.rt
		s := newSwarm(t, nil, nil, cfg)
		s.mu.Lock()
		got := s.relayAfterLocked()
		s.mu.Unlock()
		if got != c.want {
			t.Errorf("RequestTimeout %v: relays after %v, want %v", c.rt, got, c.want)
		}
	}
}

func TestRelayRedialParallel(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, &kolorelay.ServerConfig{MaxSessionDuration: time.Second})
	_, b, wa, _, g := relayedPair(t, topicOf(t.Name()), relayConfig(r.entry()), relayConfig(r.entry()))
	first := waitRelayed(t, wa, b.PublicKey(), r.key)
	g.set(b.PublicKey(), holdCtx)
	<-first.Conn().Context().Done()
	waitFor(t, 60*time.Second, "a relayed again", func() bool {
		p := wa.peer(b.PublicKey())
		return p != nil && p != first && !p.Direct()
	})
	if _, passed := g.count(b.PublicKey()); passed != 0 {
		t.Fatal("a direct Connect passed the gate")
	}
}

func TestRelayUpgradesToDirect(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	r := startRelay(t, &kolorelay.ServerConfig{MaxSessionDuration: 3 * time.Second})
	a, b, wa, wb, g := relayedPair(t, topicOf(t.Name()), relayConfig(r.entry()), relayConfig(r.entry()))
	first := waitRelayed(t, wa, b.PublicKey(), r.key)
	release := make(chan struct{})
	g.set(b.PublicKey(), holdUntil(release))
	<-first.Conn().Context().Done()
	var second *Peer
	waitFor(t, 60*time.Second, "a relayed again", func() bool {
		second = wa.peer(b.PublicKey())
		return second != nil && second != first && !second.Direct()
	})
	close(release)
	waitDirect(t, wa, b.PublicKey())
	waitDirect(t, wb, a.PublicKey())
	waitFor(t, 10*time.Second, "the relayed peer replaced", func() bool {
		wa.mu.Lock()
		defer wa.mu.Unlock()
		for _, e := range wa.events {
			if e.Kind == Lost && e.Peer == second {
				return errors.Is(e.Err, ErrDuplicate)
			}
		}
		return false
	})
}

func TestRelayAdmitKeepsDirectDial(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	a := newSwarm(t, srv, nil, relayConfig(r.entry()))
	b := newSwarm(t, srv, nil, relayConfig(r.entry()))
	release, dialing := make(chan struct{}), make(chan struct{})
	var once sync.Once
	newGate(a).set(b.PublicKey(), func(ctx context.Context) error {
		once.Do(func() { close(dialing) })
		return holdUntil(release)(ctx)
	})
	// b's Connect fails only once a's is in progress, so b's relayed connection meets a's running dial.
	newGate(b).set(a.PublicKey(), func(ctx context.Context) error {
		holdUntil(dialing)(ctx)
		return kolodht.ErrUnreachable
	})
	wa, wb := watch(t, a), watch(t, b)
	join(t, a, topic, nil)
	join(t, b, topic, nil)
	waitRelayed(t, wa, b.PublicKey(), r.key)
	close(release)
	waitDirect(t, wa, b.PublicKey())
	waitDirect(t, wb, a.PublicKey())
}

func TestRelaySizingPerAddress(t *testing.T) {
	checkGoroutines(t)
	t.Run("default listener", func(t *testing.T) {
		r := listenRelay(t, &kolorelay.ServerConfig{})
		srv := newServer(t)
		topic := topicOf(t.Name())
		b := newSwarm(t, srv, nil, relayConfig(r.entry()))
		c := newSwarm(t, srv, nil, relayConfig(r.entry()))
		wb, wc := watch(t, b), watch(t, c)
		join(t, b, topic, &JoinOptions{Announce: true})
		join(t, c, topic, &JoinOptions{Announce: true})
		waitFor(t, 20*time.Second, "two reservations", func() bool { return wb.held(r.key) && wc.held(r.key) })
		a := newSwarm(t, srv, nil, relayConfig(r.entry()))
		g := newGate(a)
		g.set(b.PublicKey(), refuseConn)
		g.set(c.PublicKey(), refuseConn)
		wa := watch(t, a)
		join(t, a, topic, &JoinOptions{Lookup: true})
		waitRelayed(t, wa, b.PublicKey(), r.key)
		waitRelayed(t, wa, c.PublicKey(), r.key)

		d := newSwarm(t, srv, nil, relayConfig(r.entry()))
		wd := watch(t, d)
		join(t, d, topic, &JoinOptions{Announce: true})
		waitFor(t, 20*time.Second, "the fifth connection refused", func() bool { return wd.sawRelay(r.key, ErrLost) })
		if wd.held(r.key) {
			t.Fatal("a fifth connection from one address was admitted")
		}
		e := newSwarm(t, srv, nil, relayConfig(r.entry()))
		newGate(e).set(b.PublicKey(), refuseConn)
		we := watch(t, e)
		join(t, e, topic, &JoinOptions{Lookup: true})
		waitFor(t, 30*time.Second, "e's relay dial refused", func() bool {
			we.mu.Lock()
			defer we.mu.Unlock()
			for _, ev := range we.events {
				if ev.Kind == Unreachable && bytes.Equal(ev.PublicKey, b.PublicKey()) {
					return true
				}
			}
			return false
		})
		if we.peer(b.PublicKey()) != nil {
			t.Fatal("a session over the per-address limit")
		}
	})
	t.Run("sized", func(t *testing.T) {
		// Three members behind 127.0.0.1, each starting up to two relayed partners: (2 + 2) × 3 per address,
		// and at least 2 × 3 reservations + 3 sessions in all.
		r := listenRelay(t, &kolorelay.ServerConfig{Secure: &kolosecure.Config{Transport: &kolotransport.Config{
			MaxConns: 12, MaxConnsPerIP: 12, MaxDialed: 1, MaxIncomingStreams: 2,
			MaxStreamReceiveWindow: 64 << 10, MaxConnReceiveWindow: 256 << 10,
		}}})
		srv := newServer(t)
		topic := topicOf(t.Name())
		var ss []*Swarm
		var ws []*watcher
		for range 3 {
			s := newSwarm(t, srv, nil, relayConfig(r.entry()))
			ss = append(ss, s)
			ws = append(ws, watch(t, s))
		}
		for _, s := range ss {
			g := newGate(s)
			for _, o := range ss {
				g.set(o.PublicKey(), refuseConn)
			}
		}
		for _, s := range ss {
			join(t, s, topic, nil)
		}
		for i, w := range ws {
			for j, o := range ss {
				if i != j {
					waitRelayed(t, w, o.PublicKey(), r.key)
				}
			}
		}
	})
}

func TestRelayRenewalNotAFailure(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	const lifetime = time.Second
	var mu sync.Mutex
	var reserves []time.Time
	var bkey atomic.Value
	r := startRelay(t, &kolorelay.ServerConfig{ReservationLifetime: lifetime, AllowReserve: func(k ed25519.PublicKey) bool {
		if want, _ := bkey.Load().(string); want == string(k) {
			mu.Lock()
			reserves = append(reserves, time.Now())
			mu.Unlock()
		}
		return true
	}})
	srv := newServer(t)
	topic := topicOf(t.Name())
	cfg := relayConfig(r.entry())
	cfg.RetryMin, cfg.RetryMax = time.Second, time.Hour
	bid := ident(t)
	bkey.Store(string(bid.PublicKey()))
	b := newSwarm(t, srv, bid, cfg)
	join(t, b, topic, &JoinOptions{Announce: true})
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(reserves)
	}
	waitFor(t, 60*time.Second, "five renewals", func() bool { return count() >= 6 })
	mu.Lock()
	for i := 1; i < 6; i++ {
		// Each renewal follows the end by RetryMin and a handshake; a failure backoff would add up to RetryMin·(2^n - 1).
		if extra := reserves[i].Sub(reserves[i-1]) - lifetime - cfg.RetryMin; extra > time.Second {
			t.Errorf("renewal %d came %v after RetryMin", i, extra)
		}
	}
	mu.Unlock()
	c := newSwarm(t, srv, nil, relayConfig(r.entry()))
	newGate(c).set(b.PublicKey(), refuseConn)
	wc := watch(t, c)
	join(t, c, topic, &JoinOptions{Lookup: true})
	p := waitRelayed(t, wc, b.PublicKey(), r.key)
	// The session outlives the reservation it came through.
	n := count()
	waitFor(t, 30*time.Second, "two more renewals", func() bool { return count() >= n+2 })
	if wc.peer(b.PublicKey()) != p || p.Conn().Context().Err() != nil {
		t.Fatal("the relayed peer ended with its reservation")
	}
}

func TestRelayDownDoesNotThrottleDirect(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	dead := downRelay(t)
	srv := newServer(t)
	topic := topicOf(t.Name())
	cfg := relayConfig(dead)
	cfg.MaxConnecting = 1
	cfg.RetryMin, cfg.RetryMax = time.Minute, time.Hour
	a := newSwarm(t, srv, nil, cfg)
	b := newSwarm(t, srv, nil, nil)
	c := newSwarm(t, srv, nil, nil)
	d := newSwarm(t, srv, nil, nil)
	g := newGate(a)
	g.set(b.PublicKey(), refuseConn)
	g.set(d.PublicKey(), refuseConn)
	wa := watch(t, a)
	cDirect := make(chan struct{})
	inRelay := make(chan struct{}, 1)
	log := logRelays(a, func(ctx context.Context, _, _ ed25519.PublicKey) {
		inRelay <- struct{}{}
		select {
		case <-cDirect:
		case <-ctx.Done():
		}
	})
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	<-inRelay
	join(t, c, topic, &JoinOptions{Announce: true})
	waitDirect(t, wa, c.PublicKey())
	close(cDirect)
	waitFor(t, 30*time.Second, "the relay marked down", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.relays[0].down > 0 && a.relayed == 0
	})
	join(t, d, topic, &JoinOptions{Announce: true})
	waitFor(t, 30*time.Second, "d's Connect failed and released", func() bool {
		n, _ := g.count(d.PublicKey())
		a.mu.Lock()
		defer a.mu.Unlock()
		return n > 0 && a.slots[key(d.PublicKey())] == nil
	})
	if n := log.count(); n != 1 {
		t.Fatalf("%d relay dials, want 1: a down relay is not dialed before its backoff", n)
	}
}

func TestRelayReserveBeforeAnnounce(t *testing.T) {
	checkGoroutines(t)
	r1, r2 := startRelay(t, nil), startRelay(t, nil)
	a := newSwarm(t, newServer(t), nil, relayConfig(r1.entry(), r2.entry()))
	join(t, a, topicOf(t.Name()), &JoinOptions{Announce: true})
	for _, r := range []*testRelay{r1, r2} {
		if err := rawDial(t, r.entry(), a.PublicKey()); err != nil {
			t.Fatalf("Dial right after Join: %v", err)
		}
	}
}

func TestRelayLookupOnlyNoReservation(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	a := newSwarm(t, newServer(t), nil, relayConfig(r.entry()))
	wa := watch(t, a)
	join(t, a, topicOf(t.Name()), &JoinOptions{Lookup: true})
	if err := rawDial(t, r.entry(), a.PublicKey()); !errors.Is(err, kolorelay.ErrUnavailable) {
		t.Fatalf("Dial to a lookup-only swarm: %v, want ErrUnavailable", err)
	}
	if wa.kinds(RelayChanged) != 0 {
		t.Fatal("a lookup-only swarm queued RelayChanged")
	}
}

func TestRelaySimultaneous(t *testing.T) {
	checkGoroutines(t)
	r1, r2 := startRelay(t, nil), startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	a := newSwarm(t, srv, nil, relayConfig(r1.entry(), r2.entry()))
	b := newSwarm(t, srv, nil, relayConfig(r2.entry(), r1.entry()))
	newGate(a).set(b.PublicKey(), refuseConn)
	newGate(b).set(a.PublicKey(), refuseConn)
	var arrived sync.WaitGroup
	arrived.Add(2)
	both := make(chan struct{})
	go func() {
		arrived.Wait()
		close(both)
	}()
	var once [2]sync.Once
	for i, s := range []*Swarm{a, b} {
		logRelays(s, func(ctx context.Context, _, _ ed25519.PublicKey) {
			once[i].Do(arrived.Done)
			select {
			case <-both:
			case <-ctx.Done():
			}
		})
	}
	t.Cleanup(func() {
		for i := range once {
			once[i].Do(arrived.Done)
		}
	})
	wa, wb := watch(t, a), watch(t, b)
	join(t, a, topic, nil)
	join(t, b, topic, nil)
	pa := waitRelayed(t, wa, b.PublicKey(), nil)
	pb := waitRelayed(t, wb, a.PublicKey(), nil)
	stable(t, 30*time.Second, time.Second, "one connection each", func() bool {
		qa, qb := wa.peer(b.PublicKey()), wb.peer(a.PublicKey())
		if qa != pa || qb != pb {
			pa, pb = qa, qb
			return false
		}
		return pa != nil && pb != nil
	})
	echoOver(t, pa.Conn(), pb.Conn())
	for _, s := range []*Swarm{a, b} {
		waitFor(t, 20*time.Second, "idle counts", func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			return len(s.slots) == 1 && s.hellos == 0 && len(s.helloKey) == 0 && len(s.helloSrc) == 0 && s.relayed == 0 && s.dialing == 0
		})
	}
}

func TestRelayTargetNotReserved(t *testing.T) {
	checkGoroutines(t)
	var mu sync.Mutex
	var connects []time.Time
	r := startRelay(t, &kolorelay.ServerConfig{AllowConnect: func(_, _ ed25519.PublicKey) bool {
		mu.Lock()
		connects = append(connects, time.Now())
		mu.Unlock()
		return true
	}})
	a, b, wa, _, _ := relayedPair(t, topicOf(t.Name()), relayConfig(r.entry()), nil)
	var unreachableAt time.Time
	waitFor(t, 30*time.Second, "Unreachable", func() bool {
		wa.mu.Lock()
		defer wa.mu.Unlock()
		for _, e := range wa.events {
			if e.Kind == Unreachable && bytes.Equal(e.PublicKey, b.PublicKey()) && errors.Is(e.Err, kolodht.ErrUnreachable) {
				unreachableAt = time.Now()
				return true
			}
		}
		return false
	})
	waitFor(t, 30*time.Second, "three failed relay dials", func() bool {
		mu.Lock()
		n := len(connects)
		mu.Unlock()
		a.mu.Lock()
		defer a.mu.Unlock()
		c := a.cands[key(b.PublicKey())]
		return n >= 3 && c != nil && c.fails >= 3
	})
	mu.Lock()
	defer mu.Unlock()
	if !connects[0].Before(unreachableAt) {
		t.Fatal("Unreachable before the relay dial")
	}
	for i := 1; i < len(connects); i++ {
		if gap := connects[i].Sub(connects[i-1]); gap < a.cfg.RetryMin {
			t.Fatalf("relay dials %v apart, below RetryMin", gap)
		}
	}
	if wa.peer(b.PublicKey()) != nil {
		t.Fatal("connected to a target with no reservation")
	}
}

func TestRelayUnreachableAfterChain(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, nil)
	a := newSwarm(t, srv, nil, relayConfig(r.entry()))
	newGate(a).set(b.PublicKey(), refuseConn)
	in, release := make(chan struct{}, 1), make(chan struct{})
	logRelays(a, func(ctx context.Context, _, _ ed25519.PublicKey) {
		in <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
	})
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	<-in
	waitFor(t, 10*time.Second, "the direct path done", func() bool {
		for _, st := range goroutines() {
			if strings.Contains(st, "kolo-swarm.(*Swarm).dialVia(") {
				return false
			}
		}
		return true
	})
	// Every event is queued with mu held, so holding it lets the queue be read whole.
	queued := func(d time.Duration) (kinds []EventKind) {
		a.mu.Lock()
		defer a.mu.Unlock()
		for {
			ctx, cancel := context.WithTimeout(context.Background(), d)
			ev, err := a.events.Pop(ctx, nil)
			cancel()
			if err != nil {
				return kinds
			}
			kinds = append(kinds, ev.Kind)
		}
	}
	if slices.Contains(queued(10*time.Millisecond), Unreachable) {
		t.Fatal("Unreachable queued while the relay dial was still running")
	}
	close(release)
	waitFor(t, 30*time.Second, "Unreachable after the relay failed", func() bool {
		return slices.Contains(queued(10*time.Millisecond), Unreachable)
	})
}

func TestRelayWrongKey(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	wrong := Relay{Addr: startRelay(t, nil).addr, PublicKey: ident(t).PublicKey()}
	cfg := func() *Config { return relayConfig(wrong, r.entry()) }
	_, b, wa, wb, _ := relayedPair(t, topicOf(t.Name()), cfg(), cfg())
	waitRelayed(t, wa, b.PublicKey(), r.key)
	waitFor(t, 30*time.Second, "RelayChanged for the wrong key", func() bool { return wb.sawRelay(wrong.PublicKey, kolosecure.ErrUnexpectedPeer) })
	if wb.held(wrong.PublicKey) {
		t.Fatal("a reservation at a relay with another key")
	}
}

func TestRelaySmallOrderKey(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	small := make(ed25519.PublicKey, ed25519.PublicKeySize)
	small[0] = 1 // the identity point
	bad := Relay{Addr: r.addr, PublicKey: small}
	srv := newServer(t)
	topic := topicOf(t.Name())
	a := newSwarm(t, srv, nil, relayConfig(bad))
	b := newSwarm(t, srv, nil, nil)
	g := newGate(a)
	g.set(b.PublicKey(), refuseConn)
	log := logRelays(a, nil)
	wa := watch(t, a)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, nil)
	waitFor(t, 20*time.Second, "ErrInvalidConfig", func() bool { return wa.sawRelay(small, ErrInvalidConfig) })
	waitFor(t, 30*time.Second, "b's Connect failed and released", func() bool {
		n, _ := g.count(b.PublicKey())
		a.mu.Lock()
		defer a.mu.Unlock()
		return n > 0 && a.slots[key(b.PublicKey())] == nil
	})
	a.mu.Lock()
	off, run := a.relays[0].off, a.relays[0].run
	a.mu.Unlock()
	if !off || run != nil || log.count() != 0 {
		t.Fatalf("relay still in use: off %v, run %v, %d dials", off, run != nil, log.count())
	}
	if n := len(wa.relayEvents(small)); n != 1 {
		t.Fatalf("%d RelayChanged, want 1", n)
	}
}

func TestRelayAllow(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	bid := ident(t)
	cfg := relayConfig(r.entry())
	cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool { return !bytes.Equal(k, bid.PublicKey()) }
	cfg.DHT.Secure.Transport.AcceptFunc = func(netip.AddrPort) bool { return false }
	a := newSwarm(t, srv, nil, cfg)
	wa := watch(t, a)
	join(t, a, topic, &JoinOptions{Announce: true})
	ctx := testCtx(t, 30*time.Second)
	if c, err := kolorelay.Dial(ctx, r.addr, r.key, bid, a.PublicKey(), nil); !errors.Is(err, kolorelay.ErrUnavailable) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("Dial with a refused key: %v, want ErrUnavailable", err)
	}
	c := newSwarm(t, srv, nil, relayConfig(r.entry()))
	newGate(c).set(a.PublicKey(), refuseConn)
	join(t, c, topic, &JoinOptions{Lookup: true})
	waitRelayed(t, wa, c.PublicKey(), r.key)
	if wa.peer(bid.PublicKey()) != nil {
		t.Fatal("a refused key was admitted")
	}
}

func TestRelayLeaveReleases(t *testing.T) {
	checkGoroutines(t)
	r1, r2 := startRelay(t, nil), startRelay(t, nil)
	a := newSwarm(t, newServer(t), nil, relayConfig(r1.entry(), r2.entry()))
	wa := watch(t, a)
	topic := topicOf(t.Name())
	join(t, a, topic, &JoinOptions{Announce: true})
	a.Leave(topic)
	for _, r := range []*testRelay{r1, r2} {
		waitFor(t, 20*time.Second, "ErrClosed", func() bool { return wa.sawRelay(r.key, ErrClosed) })
		waitFor(t, 20*time.Second, "the reservation released", func() bool {
			return errors.Is(rawDial(t, r.entry(), a.PublicKey()), kolorelay.ErrUnavailable)
		})
	}
	join(t, a, topic, &JoinOptions{Announce: true})
	for _, r := range []*testRelay{r1, r2} {
		if err := rawDial(t, r.entry(), a.PublicKey()); err != nil {
			t.Fatalf("Dial after a new Join: %v", err)
		}
	}
}

func TestRelayTryLaterNoRelay(t *testing.T) {
	checkGoroutines(t)
	var connects atomic.Int32
	r := startRelay(t, &kolorelay.ServerConfig{AllowConnect: func(_, _ ed25519.PublicKey) bool {
		connects.Add(1)
		return true
	}})
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, relayConfig(r.entry()))
	a := newSwarm(t, srv, nil, relayConfig(r.entry()))
	g := newGate(a)
	g.set(b.PublicKey(), func(context.Context) error { return kolodht.ErrTryLater })
	log := logRelays(a, nil)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitFor(t, 30*time.Second, "the Connect answered try later", func() bool {
		n, _ := g.count(b.PublicKey())
		a.mu.Lock()
		defer a.mu.Unlock()
		return n > 0 && a.slots[key(b.PublicKey())] == nil
	})
	if log.count() != 0 || connects.Load() != 0 {
		t.Fatalf("%d relay dials after try later", log.count())
	}
}

func TestRelayDialBound(t *testing.T) {
	checkGoroutines(t)
	var mu sync.Mutex
	var held, most int
	release := make(chan struct{})
	var aKey atomic.Value
	hold := func(from, _ ed25519.PublicKey) bool {
		if k, _ := aKey.Load().(string); k != string(from) {
			return true
		}
		mu.Lock()
		held++
		most = max(most, held)
		mu.Unlock()
		<-release
		mu.Lock()
		held--
		mu.Unlock()
		return true
	}
	r1 := startRelay(t, &kolorelay.ServerConfig{AllowConnect: hold})
	r2 := startRelay(t, &kolorelay.ServerConfig{AllowConnect: hold})
	t.Cleanup(func() { close(release) })
	srv := newServer(t)
	topic := topicOf(t.Name())
	aid := ident(t)
	aKey.Store(string(aid.PublicKey()))
	cfg := relayConfig(r1.entry(), r2.entry())
	a := newSwarm(t, srv, aid, cfg)
	g := newGate(a)
	for range 4 {
		x := newSwarm(t, srv, nil, relayConfig(r1.entry(), r2.entry()))
		g.set(x.PublicKey(), refuseConn)
		join(t, x, topic, &JoinOptions{Announce: true})
	}
	wa := watch(t, a)
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitFor(t, 30*time.Second, "MaxConnecting held relay dials", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return held == cfg.MaxConnecting
	})
	c := newSwarm(t, srv, nil, nil)
	join(t, c, topic, &JoinOptions{Announce: true})
	waitDirect(t, wa, c.PublicKey())
	a.Leave(topic)
	waitFor(t, 30*time.Second, "chains canceled", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.relayed == 0
	})
	mu.Lock()
	defer mu.Unlock()
	if most > cfg.MaxConnecting {
		t.Fatalf("%d relay dials at once, MaxConnecting is %d", most, cfg.MaxConnecting)
	}
}

// fedSwarm returns an announcing swarm with two relays whose reservations hand it the connections sent on the channel.
func fedSwarm(t *testing.T, edit func(*Config)) (a *Swarm, aid *koloid.Identity, ch chan Conn, relays [2]*testRelay, srv *kolodht.Node, topic Topic) {
	t.Helper()
	relays = [2]*testRelay{startRelay(t, nil), startRelay(t, nil)}
	srv = newServer(t)
	topic = topicOf(t.Name())
	cfg := relayConfig(relays[0].entry(), relays[1].entry())
	if edit != nil {
		edit(cfg)
	}
	aid = ident(t)
	a = newSwarm(t, srv, aid, cfg)
	ch = feed(a)
	join(t, a, topic, &JoinOptions{Announce: true})
	return
}

// attachedFar starts a swarm that found a on topic and attaches the far side of a fed connection.
func attachedFar(t *testing.T, srv *kolodht.Node, a *Swarm, topic Topic) (*Swarm, *koloid.Identity) {
	t.Helper()
	xid := ident(t)
	x := newSwarm(t, srv, xid, nil)
	newGate(x).set(a.PublicKey(), refuseConn)
	wx := watch(t, x)
	join(t, x, topic, &JoinOptions{Lookup: true})
	waitFor(t, 20*time.Second, "x found a", func() bool { return wx.kinds(Found) > 0 })
	return x, xid
}

func TestRelayInboundLimits(t *testing.T) {
	t.Run("MaxInbound over two relays", func(t *testing.T) {
		checkGoroutines(t)
		a, aid, ch, relays, srv, topic := fedSwarm(t, func(c *Config) { c.MaxPeers, c.MaxInbound = 4, 1 })
		wa := watch(t, a)
		x, xid := attachedFar(t, srv, a, topic)
		ca, cx := fedPair(t, aid, xid, relays[0].key)
		errc := make(chan error, 1)
		go func() { errc <- x.Attach(testCtx(t, 10*time.Second), cx, true) }()
		ch <- ca
		if err := <-errc; err != nil {
			t.Fatalf("Attach: %v", err)
		}
		waitRelayed(t, wa, xid.PublicKey(), relays[0].key)
		_, yid := attachedFar(t, srv, a, topic)
		ca2, cy := fedPair(t, aid, yid, relays[1].key)
		ch <- ca2
		if code := closeCodeOf(t, cy, 10*time.Second); code != codeFull {
			t.Fatalf("second relayed inbound closed with %d, want %d", code, codeFull)
		}
	})
	t.Run("MaxHandshakesPerIP per relay", func(t *testing.T) {
		checkGoroutines(t)
		a, aid, ch, relays, _, _ := fedSwarm(t, func(c *Config) { c.MaxHandshakesPerIP = 2 })
		var far []*kolosecure.Conn
		for range 3 {
			ca, cx := fedPair(t, aid, ident(t), relays[0].key)
			ch <- ca
			far = append(far, cx)
		}
		if code := closeCodeOf(t, far[2], 10*time.Second); code != codeFull {
			t.Fatalf("third hello through one relay closed with %d, want %d", code, codeFull)
		}
		a.mu.Lock()
		n := a.helloSrc["relay "+string(relays[0].key)]
		a.mu.Unlock()
		if n > 2 {
			t.Fatalf("%d hellos through one relay", n)
		}
	})
	t.Run("MaxPeers", func(t *testing.T) {
		checkGoroutines(t)
		a, aid, ch, relays, srv, topic := fedSwarm(t, func(c *Config) { c.MaxPeers = 1 })
		wa := watch(t, a)
		x, xid := attachedFar(t, srv, a, topic)
		ca, cx := fedPair(t, aid, xid, relays[0].key)
		errc := make(chan error, 1)
		go func() { errc <- x.Attach(testCtx(t, 10*time.Second), cx, true) }()
		ch <- ca
		if err := <-errc; err != nil {
			t.Fatalf("Attach: %v", err)
		}
		waitRelayed(t, wa, xid.PublicKey(), relays[0].key)
		ca2, cy := fedPair(t, aid, ident(t), relays[1].key)
		ch <- ca2
		if code := closeCodeOf(t, cy, 10*time.Second); code != codeFull {
			t.Fatalf("relayed inbound past MaxPeers closed with %d, want %d", code, codeFull)
		}
	})
}

func TestRelayedKeyIsProved(t *testing.T) {
	checkGoroutines(t)
	a, aid, ch, relays, _, _ := fedSwarm(t, nil)
	for _, k := range []ed25519.PublicKey{a.PublicKey(), make(ed25519.PublicKey, 31)} {
		ca, cx := fedPair(t, aid, ident(t), relays[0].key)
		ch <- keyed{viaRelay: ca.(viaRelay), key: k}
		if code := closeCodeOf(t, cx, 10*time.Second); code != codeRefused {
			t.Fatalf("a relayed key of %d bytes closed with %d, want %d", len(k), code, codeRefused)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hellos != 0 || len(a.slots) != 0 {
		t.Fatal("a hello ran on an unusable key")
	}
}

func TestRelayHelloWindow(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	bid, aid := identPair(t)
	b := newSwarm(t, srv, bid, relayConfig(r.entry()))
	var slow atomic.Bool
	slow.Store(true)
	b.hooks.quick.Store(int64(300 * time.Millisecond))
	b.hooks.afterHello = func() {
		if slow.Load() {
			time.Sleep(600 * time.Millisecond)
		}
	}
	a := newSwarm(t, srv, aid, relayConfig(r.entry()))
	newGate(a).set(b.PublicKey(), refuseConn)
	log := logRelays(a, nil)
	wa, wb := watch(t, a), watch(t, b)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitFor(t, 30*time.Second, "a failed relayed hello", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		c := a.cands[key(bid.PublicKey())]
		return log.count() > 0 && c != nil && c.fails > 0 && a.slots[key(bid.PublicKey())] == nil
	})
	if wa.kinds(Connected)+wb.kinds(Connected) != 0 {
		t.Fatal("admitted past the hello window")
	}
	slow.Store(false)
	waitRelayed(t, wa, bid.PublicKey(), r.key)
}

func TestRelaySameIdentity(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	id := ident(t)
	var mu sync.Mutex
	var reserves []time.Time
	r := startRelay(t, &kolorelay.ServerConfig{AllowReserve: func(k ed25519.PublicKey) bool {
		if bytes.Equal(k, id.PublicKey()) {
			mu.Lock()
			reserves = append(reserves, time.Now())
			mu.Unlock()
		}
		return true
	}})
	srv := newServer(t)
	topic := topicOf(t.Name())
	cfg := func() *Config {
		c := relayConfig(r.entry())
		c.RetryMin, c.RetryMax = time.Second, time.Hour
		return c
	}
	start := time.Now()
	for range 2 {
		join(t, newSwarm(t, srv, id, cfg()), topic, &JoinOptions{Announce: true})
	}
	const n = 6
	waitFor(t, 60*time.Second, "reservations in turn", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(reserves) >= n
	})
	mu.Lock()
	elapsed := reserves[n-1].Sub(start)
	mu.Unlock()
	// Each swarm reserves at most once per RetryMin after it was replaced, so n reservations take (n - 2) / 2 of them.
	if min := time.Duration(n-2) / 2 * time.Second; elapsed < min {
		t.Fatalf("%d reservations in %v, faster than the backoff allows (%v)", n, elapsed, min)
	}
}

func TestRelayNameFirstAddress(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	port := netip.MustParseAddrPort(r.addr).Port()
	useResolver(t, fakeResolver{"relay.test": {netip.MustParseAddr("240.0.0.1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("198.18.0.9")}})
	named := Relay{Addr: fmt.Sprintf("relay.test:%d", port), PublicKey: r.key}
	_, b, wa, wb, _ := relayedPair(t, topicOf(t.Name()), relayConfig(named), relayConfig(named))
	waitFor(t, 20*time.Second, "b's reservation through the name", func() bool { return wb.held(r.key) })
	waitRelayed(t, wa, b.PublicKey(), r.key)
}

func TestRelayEndedReservationDrains(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	aid := ident(t)
	a := newSwarm(t, srv, aid, relayConfig(r.entry()))
	ready := make(chan Conn, 1)
	var calls atomic.Int32
	var first atomic.Pointer[kolorelay.Reservation]
	ended := errors.Join(kolorelay.ErrReservationEnded, errors.New("test end"))
	a.mu.Lock()
	a.hooks.accept = func(ctx context.Context, res *kolorelay.Reservation) (Conn, error) {
		switch calls.Add(1) {
		case 1:
			first.Store(res)
			return nil, ended
		case 2:
			select {
			case c := <-ready:
				return c, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case 3:
			return nil, ended
		}
		c, err := res.Accept(ctx)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	a.mu.Unlock()
	wa := watch(t, a)
	join(t, a, topic, &JoinOptions{Announce: true})
	x, xid := attachedFar(t, srv, a, topic)
	ca, cx := fedPair(t, aid, xid, r.key)
	errc := make(chan error, 1)
	go func() { errc <- x.Attach(testCtx(t, 10*time.Second), cx, true) }()
	ready <- ca
	if err := <-errc; err != nil {
		t.Fatalf("Attach after the end: %v", err)
	}
	p := waitRelayed(t, wa, xid.PublicKey(), r.key)
	listed := func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		run := a.relays[0].run
		return run != nil && run.res[first.Load()] != nil
	}
	if !listed() {
		t.Fatal("the ended reservation left the list while its connection is open")
	}
	p.Conn().Close()
	waitFor(t, 20*time.Second, "the ended reservation dropped", func() bool { return !listed() })
}

func TestRelayCloseParallel(t *testing.T) {
	longTest(t)
	t.Run("vanished peers", func(t *testing.T) {
		checkGoroutines(t)
		r1, r2 := startRelay(t, nil), startRelay(t, nil)
		p1, p2 := startProxy(t, r1.addr), startProxy(t, r2.addr)
		srv := newServer(t)
		topic := topicOf(t.Name())
		a := newSwarm(t, srv, nil, relayConfig(r1.entry(), r2.entry()))
		wa := watch(t, a)
		join(t, a, topic, &JoinOptions{Announce: true})
		var far []*Swarm
		for i := range 5 {
			via := Relay{Addr: []string{p1.addr(), p2.addr()}[i%2], PublicKey: []ed25519.PublicKey{r1.key, r2.key}[i%2]}
			x := newSwarm(t, srv, nil, relayConfig(via))
			newGate(x).set(a.PublicKey(), refuseConn)
			join(t, x, topic, &JoinOptions{Lookup: true})
			far = append(far, x)
		}
		var peers []*Peer
		for _, x := range far {
			peers = append(peers, waitRelayed(t, wa, x.PublicKey(), nil))
		}
		p1.drop.Store(true)
		p2.drop.Store(true)
		start := time.Now()
		peers[4].Conn().Close()
		one := time.Since(start)
		start = time.Now()
		a.Leave(topic)
		if left := time.Since(start); left >= one {
			t.Errorf("Leave took %v, one relayed close %v", left, one)
		}
		a.Close()
		if all := time.Since(start); all >= 2*one {
			t.Fatalf("Leave and Close of four vanished relayed peers took %v, one relayed close %v", all, one)
		}
	})
	t.Run("during Reserve", func(t *testing.T) {
		checkGoroutines(t)
		a := newSwarm(t, newServer(t), nil, relayConfig(downRelay(t)))
		errc := make(chan error, 1)
		go func() { errc <- a.Join(context.Background(), topicOf(t.Name()), &JoinOptions{Announce: true}) }()
		waitFor(t, 10*time.Second, "Reserve in progress", func() bool {
			for _, st := range goroutines() {
				if strings.Contains(st, "kolo-relay.Reserve(") {
					return true
				}
			}
			return false
		})
		a.Close()
		if err := <-errc; !errors.Is(err, ErrClosed) {
			t.Fatalf("Join during Close: %v", err)
		}
	})
	t.Run("during a chain", func(t *testing.T) {
		checkGoroutines(t)
		r := startRelay(t, nil)
		srv := newServer(t)
		topic := topicOf(t.Name())
		b := newSwarm(t, srv, nil, relayConfig(r.entry()))
		a := newSwarm(t, srv, nil, relayConfig(r.entry()))
		newGate(a).set(b.PublicKey(), refuseConn)
		in := make(chan struct{}, 1)
		logRelays(a, func(ctx context.Context, _, _ ed25519.PublicKey) {
			in <- struct{}{}
			<-ctx.Done()
		})
		join(t, b, topic, &JoinOptions{Announce: true})
		join(t, a, topic, &JoinOptions{Lookup: true})
		<-in
		a.Close()
	})
	t.Run("during a relayed hello", func(t *testing.T) {
		checkGoroutines(t)
		a, aid, ch, relays, _, _ := fedSwarm(t, nil)
		a.hooks.quick.Store(int64(time.Minute))
		ca, _ := fedPair(t, aid, ident(t), relays[0].key)
		ch <- ca
		waitFor(t, 10*time.Second, "a hello in progress", func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			return a.hellos == 1
		})
		a.Close()
	})
}
