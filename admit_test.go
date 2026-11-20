package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	"github.com/ciranda-dev/kolo-swarm/internal/events"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// fake is a test double for Conn: streams wait for the context, and CloseWithError records its code.
type fake struct {
	key    ed25519.PublicKey
	ctx    context.Context
	cancel context.CancelCauseFunc
	mu     sync.Mutex
	codes  []uint64
}

func newFake(key ed25519.PublicKey) *fake {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &fake{key: bytes.Clone(key), ctx: ctx, cancel: cancel}
}

func (f *fake) RemotePublicKey() ed25519.PublicKey { return bytes.Clone(f.key) }
func (f *fake) OpenStream(ctx context.Context) (*kolotransport.Stream, error) {
	return nil, f.wait(ctx)
}
func (f *fake) AcceptStream(ctx context.Context) (*kolotransport.Stream, error) {
	return nil, f.wait(ctx)
}
func (f *fake) OpenUniStream(ctx context.Context) (*kolotransport.SendStream, error) {
	return nil, f.wait(ctx)
}
func (f *fake) AcceptUniStream(ctx context.Context) (*kolotransport.ReceiveStream, error) {
	return nil, f.wait(ctx)
}
func (f *fake) Context() context.Context { return f.ctx }
func (f *fake) Close() error             { return f.CloseWithError(0, "") }
func (f *fake) CloseWithError(code uint64, _ string) error {
	f.mu.Lock()
	f.codes = append(f.codes, code)
	f.mu.Unlock()
	f.cancel(&kolotransport.Error{Err: kolotransport.ErrClosed, Code: code})
	return nil
}

func (f *fake) peerClose(code uint64) {
	f.cancel(&kolotransport.Error{Err: kolotransport.ErrPeerClosed, Code: code})
}

func (f *fake) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.ctx.Done():
		return context.Cause(f.ctx)
	}
}

func (f *fake) code() (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.codes) == 0 {
		return 0, false
	}
	return f.codes[0], true
}

// unitSwarm is a Swarm without a node, joined to topic, for admission and event tests.
func unitSwarm(t *testing.T, cfg *Config, topic Topic) *Swarm {
	t.Helper()
	c, err := cfg.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tctx, tcancel := context.WithCancel(ctx)
	t.Cleanup(tcancel)
	return &Swarm{
		cfg:      c,
		ctx:      ctx,
		cancel:   cancel,
		events:   events.New[Event](c.MaxEvents, c.MaxEvents),
		helloSrc: map[string]int{},
		wake:     make(chan struct{}, 1),
		topics:   map[Topic]*topicState{topic: {opts: JoinOptions{Announce: true, Lookup: true, MaxPeers: c.MaxPeers}, ctx: tctx, cancel: tcancel}},
		slots:    map[key]*slot{},
		helloKey: map[key]int{},
		cands:    map[key]*cand{},
		past:     map[key]*history{},
	}
}

func nextEvent(t *testing.T, s *Swarm) (Event, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ev, err := s.Next(ctx)
	return ev, err == nil
}

func TestArbiterRules(t *testing.T) {
	topic := topicOf("unit")
	k := key(ident(t).PublicKey())
	tests := []struct {
		name                 string
		firstDirect, direct  bool
		follow, wantReplaced bool
	}{
		{"direct replaces direct", true, true, false, true},
		{"attached replaces attached", false, false, false, true},
		{"direct replaces attached", false, true, false, true},
		{"attached never replaces direct", true, false, false, false},
		{"follower takes what the arbiter kept", true, false, true, true},
	}
	for _, tt := range tests {
		s := unitSwarm(t, nil, topic)
		c1, c2 := newFake(k[:]), newFake(k[:])
		if _, _, err := s.admit(c1, k, netip.AddrPort{}, false, tt.firstDirect, []Topic{topic}, false, generation{}); err != nil {
			t.Fatal(err)
		}
		if ev, ok := nextEvent(t, s); !ok || ev.Kind != Connected || ev.Peer.conn != c1 {
			t.Fatalf("%s: first event %+v", tt.name, ev)
		}
		_, code, err := s.admit(c2, k, netip.AddrPort{}, false, tt.direct, []Topic{topic}, tt.follow, generation{n: 1 << 62})
		if !tt.wantReplaced {
			if !errors.Is(err, ErrDuplicate) || code != codeDuplicate {
				t.Fatalf("%s: admit = %d, %v; want refusal with code 2", tt.name, code, err)
			}
			if c1.ctx.Err() != nil {
				t.Fatalf("%s: kept connection closed", tt.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got, ok := c1.code(); !ok || got != codeDuplicate {
			t.Fatalf("%s: old connection closed with %d, %v", tt.name, got, ok)
		}
		lost, ok := nextEvent(t, s)
		if !ok || lost.Kind != Lost || lost.Peer.conn != c1 || !errors.Is(lost.Err, ErrDuplicate) {
			t.Fatalf("%s: second event %+v, want Lost of the old peer", tt.name, lost)
		}
		conn, ok := nextEvent(t, s)
		if !ok || conn.Kind != Connected || conn.Peer.conn != c2 {
			t.Fatalf("%s: third event %+v, want Connected of the new peer", tt.name, conn)
		}
		if _, ok := nextEvent(t, s); ok {
			t.Fatalf("%s: extra event", tt.name)
		}
		if n := len(s.slots); n != 1 {
			t.Fatalf("%s: %d slots", tt.name, n)
		}
	}
}

func TestLostBeforeRead(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, nil, topic)
	k := key(ident(t).PublicKey())
	c := newFake(k[:])
	if _, _, err := s.admit(c, k, netip.AddrPort{}, true, true, []Topic{topic}, false, generation{}); err != nil {
		t.Fatal(err)
	}
	c.peerClose(codeNormal)
	waitFor(t, time.Second, "slot freed", func() bool {
		n, in := s.slotCounts()
		return n == 0 && in == 0
	})
	if n := s.events.Len(); n != 0 {
		t.Fatalf("%d events still queued for a peer lost before Next read it", n)
	}
	if ev, ok := nextEvent(t, s); ok {
		t.Fatalf("got %v for a peer lost before Next read it", ev.Kind)
	}
}

func TestLostAfterRead(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, nil, topic)
	k := key(ident(t).PublicKey())
	c := newFake(k[:])
	s.admit(c, k, netip.AddrPort{}, true, true, []Topic{topic}, false, generation{})
	ev, ok := nextEvent(t, s)
	if !ok || ev.Kind != Connected {
		t.Fatal("no Connected")
	}
	c.peerClose(7)
	waitFor(t, time.Second, "Lost", func() bool { return s.events.Len() == 1 })
	lost, ok := nextEvent(t, s)
	if !ok || lost.Kind != Lost || lost.Peer != ev.Peer || lost.Err != ErrLost {
		t.Fatalf("Lost event %+v", lost)
	}
}

// TestLostErrHasNoPeerContent maps every cause of a loss to a bare sentinel.
func TestLostErrHasNoPeerContent(t *testing.T) {
	tests := []struct {
		cause error
		want  error
	}{
		{&kolotransport.Error{Err: kolotransport.ErrPeerClosed, Code: 1234567}, ErrLost},
		{&kolotransport.Error{Err: kolotransport.ErrPeerClosed, Code: codeDuplicate}, ErrDuplicate},
		{&kolotransport.Error{Err: kolotransport.ErrClosed, Code: codeDuplicate}, ErrDuplicate},
		{&kolotransport.Error{Err: kolotransport.ErrPeerClosed, Code: codeFull}, ErrRefused},
		{&kolotransport.Error{Err: kolotransport.ErrPeerClosed, Code: codeRefused}, ErrRefused},
		{&kolotransport.Error{Err: kolotransport.ErrPeerClosed, Code: codeProtocol}, ErrProtocol},
		{&kolotransport.Error{Err: kolotransport.ErrClosed, Code: 0}, ErrClosed},
		{&kolotransport.Error{Err: kolotransport.ErrTransport, Code: 99}, ErrLost},
		{errors.New("app conn: peer said 'secret 1234567'"), ErrLost},
		{context.Canceled, ErrLost},
	}
	for _, tt := range tests {
		got := lostErr(tt.cause)
		if got != tt.want {
			t.Errorf("lostErr(%v) = %v, want %v", tt.cause, got, tt.want)
		}
		if strings.Contains(got.Error(), "1234567") || strings.Contains(got.Error(), "99") || strings.Contains(got.Error(), "secret") {
			t.Errorf("lostErr(%v) = %q carries peer content", tt.cause, got)
		}
	}
	topic := topicOf("unit")
	s := unitSwarm(t, nil, topic)
	k := key(ident(t).PublicKey())
	f := newFake(k[:])
	s.admit(f, k, netip.AddrPort{}, true, true, []Topic{topic}, false, generation{})
	nextEvent(t, s)
	f.cancel(errors.New("peer text 1234567"))
	waitFor(t, time.Second, "Lost", func() bool { return s.events.Len() == 1 })
	if ev, _ := nextEvent(t, s); ev.Err != ErrLost {
		t.Fatalf("Lost.Err = %v", ev.Err)
	}
}

func TestAdmitLimits(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, &Config{MaxPeers: 3, MaxInbound: 1}, topic)
	s.topics[topic].opts.MaxPeers = 32 // so that only MaxPeers and MaxInbound bind
	admit := func(inbound bool, topics ...Topic) (uint64, error) {
		k := key(ident(t).PublicKey())
		_, code, err := s.admit(newFake(k[:]), k, netip.AddrPort{}, inbound, true, topics, false, generation{})
		return code, err
	}
	if _, err := admit(true, topic); err != nil {
		t.Fatal(err)
	}
	if code, err := admit(true, topic); !errors.Is(err, ErrRefused) || code != codeFull {
		t.Fatalf("second inbound: %d, %v", code, err)
	}
	if code, err := admit(false, topicOf("not joined")); !errors.Is(err, ErrRefused) || code != codeRefused {
		t.Fatalf("no joined topic: %d, %v", code, err)
	}
	for range 2 {
		if _, err := admit(false, topic); err != nil {
			t.Fatal(err)
		}
	}
	if code, err := admit(false, topic); !errors.Is(err, ErrRefused) || code != codeFull {
		t.Fatalf("past MaxPeers: %d, %v", code, err)
	}
	if n, in := s.slotCounts(); n != 3 || in != 1 {
		t.Fatalf("slots %d, inbound %d", n, in)
	}
}

func TestAdmitTopicLimit(t *testing.T) {
	topic, other := topicOf("unit"), topicOf("other")
	s := unitSwarm(t, nil, topic)
	s.topics[topic].opts.MaxPeers = 1
	s.topics[other] = &topicState{opts: JoinOptions{Lookup: true, MaxPeers: 8}, ctx: s.ctx, cancel: func() {}}
	admit := func(topics ...Topic) error {
		k := key(ident(t).PublicKey())
		_, _, err := s.admit(newFake(k[:]), k, netip.AddrPort{}, false, true, topics, false, generation{})
		return err
	}
	if err := admit(topic); err != nil {
		t.Fatal(err)
	}
	if err := admit(topic); !errors.Is(err, ErrRefused) {
		t.Fatalf("second peer of a full topic: %v", err)
	}
	if err := admit(topic, other); err != nil {
		t.Fatalf("peer that also shares an open topic: %v", err)
	}
}

func TestEventsBounded(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, &Config{MaxEvents: 16, MaxCandidates: 20}, topic)
	var recs []kolodht.Record
	for range 40 {
		recs = append(recs, kolodht.Record{Topic: topic, PublicKey: ident(t).PublicKey(), Addr: fakeAddr()})
	}
	s.found(topic, s.topics[topic], recs)
	if n := s.events.Len(); n != 16 {
		t.Fatalf("%d Found events queued, want MaxEvents 16", n)
	}
	if n := len(s.cands); n != 20 {
		t.Fatalf("%d candidates, want MaxCandidates 20", n)
	}
	// Connected is never dropped, even with the queue full of Found.
	k := key(ident(t).PublicKey())
	if _, _, err := s.admit(newFake(k[:]), k, netip.AddrPort{}, true, true, []Topic{topic}, false, generation{}); err != nil {
		t.Fatal(err)
	}
	if n := s.events.Len(); n != 17 {
		t.Fatalf("Connected not queued: %d events", n)
	}
	// A lookup that no longer returns a key drops it.
	s.found(topic, s.topics[topic], recs[:5])
	if n := len(s.cands); n != 5 {
		t.Fatalf("%d candidates after a smaller lookup, want 5", n)
	}
}

func TestBackoffAccounting(t *testing.T) {
	topic := topicOf("unit")
	s := unitSwarm(t, nil, topic)
	k := key(ident(t).PublicKey())
	c := &cand{topics: map[Topic]bool{topic: true}, history: history{fails: 3}}
	s.cands[k] = c
	cycle := func(code uint64, age time.Duration) {
		t.Helper()
		f := newFake(k[:])
		if _, _, err := s.admit(f, k, netip.AddrPort{}, false, true, []Topic{topic}, false, generation{}); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.slots[k].peer.admitted = time.Now().Add(-age)
		s.mu.Unlock()
		f.peerClose(code)
		waitFor(t, time.Second, "slot freed", func() bool { n, _ := s.slotCounts(); return n == 0 })
	}
	cycle(codeNormal, 20*time.Second)
	if c.fails != 1 {
		t.Fatalf("after a lasting connection fails = %d, want 1", c.fails)
	}
	cycle(codeNormal, 0)
	if c.fails != 2 {
		t.Fatalf("after a short connection fails = %d, want 2", c.fails)
	}
	// Closed as a duplicate while another connection to the key is in its hello: a real duplicate.
	before := time.Now()
	s.mu.Lock()
	s.helloKey[k] = 1
	s.mu.Unlock()
	cycle(codeDuplicate, 0)
	if c.fails != 2 {
		t.Fatalf("a replaced connection counted as a failure: fails = %d", c.fails)
	}
	if !c.next.After(before) {
		t.Fatal("a replaced connection is dialed again at once")
	}
	// Closed as a duplicate with nothing else for the key: a failure.
	s.mu.Lock()
	delete(s.helloKey, k)
	s.mu.Unlock()
	cycle(codeDuplicate, 0)
	if c.fails != 3 {
		t.Fatalf("a duplicate close with no other connection: fails = %d, want 3", c.fails)
	}
	if !c.next.After(time.Now()) {
		t.Fatal("no backoff after a lone duplicate close")
	}
}
