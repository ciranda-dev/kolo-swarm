package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolorelay "github.com/ciranda-dev/kolo-relay"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestRelayDeniedConnectBackoff(t *testing.T) {
	longTest(t)
	for _, tc := range []struct {
		name   string
		relays []Relay
	}{{"no relays", nil}, {"relays", []Relay{downRelay(t)}}} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			srv := newServer(t)
			topic := topicOf(t.Name())
			a := newSwarm(t, srv, nil, relayConfig(tc.relays...))
			b := newSwarm(t, srv, nil, nil)
			var mu sync.Mutex
			var calls []time.Time
			newGate(a).set(b.PublicKey(), func(context.Context) error {
				mu.Lock()
				calls = append(calls, time.Now())
				mu.Unlock()
				return kolodht.ErrInvalidArgument
			})
			join(t, b, topic, &JoinOptions{Announce: true})
			join(t, a, topic, &JoinOptions{Lookup: true})
			waitFor(t, 30*time.Second, "three Connect calls", func() bool {
				mu.Lock()
				defer mu.Unlock()
				return len(calls) >= 3
			})
			mu.Lock()
			defer mu.Unlock()
			for i := 1; i < len(calls); i++ {
				if gap := calls[i].Sub(calls[i-1]); gap < a.cfg.LookupInterval {
					t.Fatalf("%d Connect calls, two of them %v apart: a refused record is retried at most once per LookupInterval (%v)",
						len(calls), gap, a.cfg.LookupInterval)
				}
			}
		})
	}
}

func TestRelayBusyNoUnreachable(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	cfg := relayConfig(r.entry())
	cfg.MaxConnecting = 1
	a := newSwarm(t, srv, nil, cfg)
	b, c := newSwarm(t, srv, nil, nil), newSwarm(t, srv, nil, nil)
	g := newGate(a)
	g.set(b.PublicKey(), refuseConn)
	g.set(c.PublicKey(), refuseConn)
	first := make(chan ed25519.PublicKey, 1)
	release := make(chan struct{})
	logRelays(a, func(ctx context.Context, _, target ed25519.PublicKey) {
		select {
		case first <- target:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
	})
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, c, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	other := c.PublicKey()
	if bytes.Equal(<-first, other) {
		other = b.PublicKey()
	}
	k := key(other)
	// The one relay dial is held, so the other key's failed Connect finds none free.
	waitFor(t, 30*time.Second, "the other key's Connect failed and released", func() bool {
		n, _ := g.count(other)
		a.mu.Lock()
		defer a.mu.Unlock()
		return n > 0 && a.slots[k] == nil && a.dialing == 0
	})
	a.mu.Lock()
	cd := a.cands[k]
	var fails, later int
	var relayed bool
	if cd != nil {
		fails, later, relayed = cd.fails, cd.later, cd.relayed
	}
	a.mu.Unlock()
	if cd == nil {
		t.Fatal("the other key is no longer a candidate")
	}
	if unreachableFor(drained(a), other) {
		t.Fatal("Unreachable with no relay tried")
	}
	if fails != 0 || later != 1 || !relayed {
		t.Fatalf("fails %d, later %d, relayed %v: want a try-later release that sends the next dial to the relays", fails, later, relayed)
	}
	close(release)
}

func TestRelayTargetIsListedRelay(t *testing.T) {
	checkGoroutines(t)
	rid := ident(t)
	r := listenRelayAs(t, rid, &kolorelay.ServerConfig{Secure: loopRelaySecure()})
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, rid, nil)
	a := newSwarm(t, srv, nil, relayConfig(r.entry()))
	g := newGate(a)
	g.set(b.PublicKey(), refuseConn)
	log := logRelays(a, nil)
	wa := watch(t, a)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	k := key(b.PublicKey())
	waitFor(t, 30*time.Second, "the relay's own key failed and released", func() bool {
		n, _ := g.count(b.PublicKey())
		a.mu.Lock()
		defer a.mu.Unlock()
		c := a.cands[k]
		return n > 0 && c != nil && c.fails > 0 && a.slots[k] == nil
	})
	a.mu.Lock()
	off := a.relays[0].off
	a.mu.Unlock()
	if n := log.count(); n != 0 || off || wa.sawRelay(r.key, ErrInvalidConfig) {
		t.Fatalf("%d relay dials to the relay's own key, relay off %v", n, off)
	}
}

func TestRelayHeldStaysUp(t *testing.T) {
	checkGoroutines(t)
	a := newSwarm(t, nil, nil, relayConfig(downRelay(t)))
	r := a.relays[0]
	a.mu.Lock()
	defer a.mu.Unlock()
	r.held = true
	a.relayHealthLocked(r, context.DeadlineExceeded)
	if r.down != 0 {
		t.Fatal("a relay holding our reservation was marked down")
	}
	r.held = false
	a.relayHealthLocked(r, context.DeadlineExceeded)
	if r.down != 1 {
		t.Fatalf("down %d after a failure with no reservation held, want 1", r.down)
	}
	a.relayHealthLocked(r, kolorelay.ErrUnavailable)
	if r.down != 0 {
		t.Fatal("a status answer did not mark the relay up")
	}
}

// lateCancel is a canceled context whose first Err says it is not, so Join passes its first check and fails later.
type lateCancel struct {
	context.Context
	calls atomic.Int32
}

func (c *lateCancel) Err() error {
	if c.calls.Add(1) == 1 {
		return nil
	}
	return c.Context.Err()
}

func TestRelayKeptWhileAnnouncing(t *testing.T) {
	checkGoroutines(t)
	r := startRelay(t, nil)
	a := newSwarm(t, newServer(t), nil, relayConfig(r.entry()))
	wa := watch(t, a)
	join(t, a, topicOf(t.Name()+" announced"), &JoinOptions{Announce: true})
	waitFor(t, 20*time.Second, "held", func() bool { return wa.held(r.key) })
	run := func() *reserveRun {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.relays[0].run
	}
	held := run()
	lookup := topicOf(t.Name() + " lookup")
	join(t, a, lookup, &JoinOptions{Lookup: true})
	a.Leave(lookup)
	if run() != held {
		t.Fatal("leaving a lookup-only topic dropped the reservations")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Join(&lateCancel{Context: canceled}, topicOf(t.Name()+" failed"), &JoinOptions{Announce: true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Join with a canceled context: %v", err)
	}
	if run() != held {
		t.Fatal("a failed Join dropped the reservations of the announced topic")
	}
	if err := rawDial(t, r.entry(), a.PublicKey()); err != nil {
		t.Fatalf("Dial to a swarm still announcing: %v", err)
	}
	if wa.sawRelay(r.key, ErrClosed) {
		t.Fatal("RelayChanged with ErrClosed while an announced topic is joined")
	}
}

func TestRelayInboundSetsLastRelay(t *testing.T) {
	checkGoroutines(t)
	a, aid, ch, relays, srv, topic := fedSwarm(t, nil)
	wa := watch(t, a)
	x, xid := attachedFar(t, srv, a, topic)
	ca, cx := fedPair(t, aid, xid, relays[1].key)
	errc := make(chan error, 1)
	go func() { errc <- x.Attach(testCtx(t, 10*time.Second), cx, true) }()
	ch <- ca
	if err := <-errc; err != nil {
		t.Fatalf("Attach: %v", err)
	}
	waitRelayed(t, wa, xid.PublicKey(), relays[1].key)
	a.mu.Lock()
	next, _ := a.nextRelayLocked(key(xid.PublicKey()), xid.PublicKey(), map[*relayState]bool{})
	a.mu.Unlock()
	if next == nil || !bytes.Equal(next.key, relays[1].key) {
		t.Fatal("the next chain to a key that came in through the second relay does not start there")
	}
}

func TestRelayRetryAfterReservation(t *testing.T) {
	a := newSwarm(t, nil, nil, relayConfig(downRelay(t)))
	retryMin := a.cfg.RetryMin
	ended := errors.New("test end")
	lifetime := &kolotransport.Error{Err: kolotransport.ErrStreamReset, Code: relayLifetime}
	for _, tc := range []struct {
		name      string
		fails     int
		held      time.Duration
		end       error
		wantFails int
		lifetime  bool
	}{
		{"lasted, then failed", 5, lasting, ended, 1, false},
		{"short, then failed", 5, lasting - time.Second, ended, 6, false},
		{"lasted, lifetime end", 5, lasting, lifetime, 0, true},
		{"short, lifetime end", 5, time.Second, lifetime, 5, true},
	} {
		fails, d := a.reserveRetry(tc.fails, tc.held, tc.end)
		if fails != tc.wantFails {
			t.Errorf("%s: fails %d, want %d", tc.name, fails, tc.wantFails)
		}
		switch {
		case tc.lifetime && d != retryMin:
			t.Errorf("%s: wait %v, want RetryMin %v", tc.name, d, retryMin)
		case !tc.lifetime && fails == 1 && (d < retryMin || d >= 2*retryMin):
			t.Errorf("%s: wait %v, want the first backoff step from RetryMin %v", tc.name, d, retryMin)
		}
	}
}

func TestRelayNoUnreachableWithPeer(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	r := startRelay(t, &kolorelay.ServerConfig{MaxSessionDuration: 3 * time.Second})
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, relayConfig(r.entry()))
	a := newSwarm(t, srv, nil, relayConfig(r.entry()))
	g := newGate(a)
	g.set(b.PublicKey(), refuseConn)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	k := key(b.PublicKey())
	relayedPeer := func() *Peer {
		a.mu.Lock()
		defer a.mu.Unlock()
		if sl := a.slots[k]; sl != nil && sl.peer != nil && !sl.peer.direct {
			return sl.peer
		}
		return nil
	}
	var first *Peer
	waitFor(t, 60*time.Second, "a relayed peer", func() bool { first = relayedPeer(); return first != nil })
	waitFor(t, 20*time.Second, "both paths done", pathsDone)
	if unreachableFor(drained(a), b.PublicKey()) {
		t.Fatal("Unreachable on first contact although the relay connected")
	}
	// The next dial runs both paths at once; the direct one fails only after the relayed peer is admitted.
	admitted := make(chan struct{})
	g.set(b.PublicKey(), func(ctx context.Context) error {
		select {
		case <-admitted:
			return kolodht.ErrUnreachable
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	<-first.Conn().Context().Done()
	waitFor(t, 60*time.Second, "relayed again", func() bool { p := relayedPeer(); return p != nil && p != first })
	close(admitted)
	waitFor(t, 20*time.Second, "both paths done", pathsDone)
	if relayedPeer() == nil {
		t.Fatal("the relayed peer is gone")
	}
	if unreachableFor(drained(a), b.PublicKey()) {
		t.Fatal("Unreachable although a relayed peer holds the slot")
	}
}
