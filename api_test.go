package koloswarm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestConfigDefaults(t *testing.T) {
	c, err := (*Config)(nil).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		MaxPeers: 1258, MaxInbound: 629, MaxConnectPeers: 314, MaxConnecting: 3, MaxHandshakes: 16, MaxHandshakesPerIP: 4,
		MaxEvents: 64, HelloTimeout: 10 * time.Second, LookupInterval: 10 * time.Minute, RetryMin: time.Second, RetryMax: 10 * time.Minute,
	}
	got := c
	got.DHT = nil
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("defaults\n got %+v\nwant %+v", got, want)
	}
	if c.DHT == nil || c.DHT.MaxAnnouncements != 0 {
		t.Fatalf("DHT.MaxAnnouncements with no MaxTopics: %+v", c.DHT)
	}
	if c, _ := (&Config{MaxTopics: 7}).withDefaults(); c.DHT.MaxAnnouncements != 7 {
		t.Fatalf("DHT.MaxAnnouncements not set to MaxTopics: %+v", c.DHT)
	}
	if c, _ := (&Config{MaxPeers: 5}).withDefaults(); c.MaxInbound != 3 {
		t.Fatalf("MaxInbound for MaxPeers 5 = %d, want 3", c.MaxInbound)
	}
	for _, x := range []struct {
		cfg  Config
		want int
	}{
		{Config{MaxPeers: 1}, 0}, {Config{MaxPeers: 2}, 1}, {Config{MaxPeers: 5}, 1}, {Config{MaxPeers: 64, MaxInbound: 60}, 4},
		{Config{MaxPeers: 1024, MaxInbound: 1024}, 0}, {Config{MaxPeers: 1024}, 256},
	} {
		if c, err := x.cfg.withDefaults(); err != nil || c.MaxConnectPeers != x.want {
			t.Errorf("MaxConnectPeers for %+v = %d (%v), want %d", x.cfg, c.MaxConnectPeers, err, x.want)
		}
	}
}

func TestConfigRanges(t *testing.T) {
	bad := []Config{
		{MaxPeers: -1},
		{MaxPeers: 4, MaxInbound: 5}, {MaxInbound: -1},
		{MaxTopics: -1}, {MaxConnecting: 17}, {MaxHandshakes: 257}, {MaxCandidates: 15}, {MaxCandidates: -1},
		{DHT: &kolodht.Config{MaxAnnouncements: 5}},
		{MaxEvents: 15}, {MaxEvents: 4097},
		{HelloTimeout: time.Millisecond}, {HelloTimeout: 2 * time.Minute},
		{LookupInterval: 999 * time.Millisecond}, {LookupInterval: 2 * time.Hour},
		{RetryMin: time.Millisecond}, {RetryMin: 2 * time.Minute},
		{RetryMin: time.Second, RetryMax: 500 * time.Millisecond}, {RetryMax: 2 * time.Hour},
		{MaxTopics: 20, DHT: &kolodht.Config{MaxAnnouncements: 19}},
		{MaxHandshakesPerIP: -1}, {MaxHandshakes: 8, MaxHandshakesPerIP: 9},
		{MaxConnectPeers: -1}, {MaxPeers: 64, MaxConnectPeers: 33}, {MaxPeers: 4, MaxConnectPeers: 3}, {MaxPeers: 2, MaxInbound: 2, MaxConnectPeers: 1},
	}
	for _, c := range bad {
		if _, err := c.withDefaults(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v: err = %v, want ErrInvalidConfig", c, err)
		}
	}
	if _, err := (&Config{MaxPeers: 2, MaxInbound: 2, MaxConnectPeers: 1}).withDefaults(); err == nil || !strings.Contains(err.Error(), "unset") {
		t.Errorf("MaxConnectPeers with no room: %v", err)
	}
	good := []Config{
		{MaxPeers: 1}, {MaxPeers: 1024, MaxInbound: 1024}, {MaxPeers: 5000}, {MaxTopics: 1000}, {MaxConnecting: 16}, {MaxHandshakes: 256},
		{MaxCandidates: 16}, {MaxCandidates: 100000}, {MaxEvents: 4096}, {HelloTimeout: time.Second}, {LookupInterval: time.Hour},
		{RetryMin: 100 * time.Millisecond, RetryMax: 100 * time.Millisecond}, {MaxTopics: 16, DHT: &kolodht.Config{MaxAnnouncements: 200}},
		{MaxHandshakes: 256, MaxHandshakesPerIP: 256}, {MaxHandshakes: 2},
		{MaxConnectPeers: 1}, {MaxConnectPeers: 32}, {MaxPeers: 4, MaxConnectPeers: 2},
	}
	for _, c := range good {
		if _, err := c.withDefaults(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

func TestConfigTransport(t *testing.T) {
	c, err := (*Config)(nil).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	tc := c.DHT.Secure.Transport
	if tc.MaxDialed != 1258+16+64 || tc.MaxConns != 629+16+64 || tc.MaxMemory != kolotransport.DefaultMaxMemory {
		t.Fatalf("default transport: MaxDialed %d, MaxConns %d, MaxMemory %d", tc.MaxDialed, tc.MaxConns, tc.MaxMemory)
	}
	c, err = (&Config{MaxPeers: 1024, MaxInbound: 1024}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	tc = c.DHT.Secure.Transport
	if n := 1024 + 16 + 64; tc.MaxDialed != n || tc.MaxConns != n || tc.MaxMemory != int64(2*n)*kolotransport.DefaultMaxConnReceiveWindow {
		t.Fatalf("1024 peers: MaxDialed %d, MaxConns %d, MaxMemory %d", tc.MaxDialed, tc.MaxConns, tc.MaxMemory)
	}
	own := &kolotransport.Config{MaxDialed: 5, MaxConns: 7, MaxMemory: 64 << 20}
	in := &Config{DHT: &kolodht.Config{Secure: &kolosecure.Config{MaxPending: 8, Transport: own}}}
	if c, err = in.withDefaults(); err != nil {
		t.Fatal(err)
	}
	if tc = c.DHT.Secure.Transport; tc.MaxDialed != 5 || tc.MaxConns != 7 || tc.MaxMemory != 64<<20 || tc == own {
		t.Fatalf("set transport fields changed: %+v", tc)
	}
	c, _ = (&Config{DHT: &kolodht.Config{Secure: &kolosecure.Config{MaxPending: 8}}}).withDefaults()
	if tc = c.DHT.Secure.Transport; tc.MaxDialed != 1333+16+8 {
		t.Fatalf("MaxDialed with MaxPending 8 = %d, want %d", tc.MaxDialed, 1333+16+8)
	}
}

func TestPlaceBudget(t *testing.T) {
	for _, tc := range []struct {
		name                                   string
		cfg                                    Config
		peers, inbound, connect, dialed, conns int
	}{
		{"defaults", Config{}, 1258, 629, 314, 1338, 709},
		{"window growth", Config{DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{WindowGrowth: true}}}}, 1173, 587, 293, 1253, 667},
		{"MaxInbound set", Config{MaxInbound: 100}, 1888 - 100, 100, 447, 1888 - 100 + 80, 100 + 80},
		{"smaller MaxMemory", Config{DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{MaxMemory: 256 << 20}}}}, 234, 117, 58, 314, 197},
		{"set MaxPeers", Config{MaxPeers: 5000}, 5000, 2500, 1250, 5080, 2580},
	} {
		c, err := tc.cfg.withDefaults()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		tr := c.DHT.Secure.Transport
		if c.MaxPeers != tc.peers || c.MaxInbound != tc.inbound || c.MaxConnectPeers != tc.connect || tr.MaxDialed != tc.dialed || tr.MaxConns != tc.conns {
			t.Errorf("%s: MaxPeers %d, MaxInbound %d, MaxConnectPeers %d, MaxDialed %d, MaxConns %d; want %d, %d, %d, %d, %d",
				tc.name, c.MaxPeers, c.MaxInbound, c.MaxConnectPeers, tr.MaxDialed, tr.MaxConns, tc.peers, tc.inbound, tc.connect, tc.dialed, tc.conns)
		}
		if tr.MaxMemory < int64(tr.MaxDialed+tr.MaxConns)*kolotransport.DefaultMaxConnReceiveWindow {
			t.Errorf("%s: MaxMemory %d is below the windows", tc.name, tr.MaxMemory)
		}
	}
	if _, err := (&Config{MaxInbound: 1000}).withDefaults(); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("MaxInbound above the derived places: %v", err)
	}
	small := &kolotransport.Config{MaxConnReceiveWindow: 64 << 10}
	if c, err := (&Config{DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: small}}}).withDefaults(); err != nil || c.DHT.Secure.Transport.MaxDialed > 10000 {
		t.Errorf("small windows: %v, %+v", err, c.DHT.Secure.Transport)
	}
}

func TestNewManyPeers(t *testing.T) {
	checkGoroutines(t)
	s, err := New(testCtx(t, 5*time.Second), "127.0.0.1:0", ident(t), &Config{MaxPeers: 1024, MaxInbound: 1024, MaxHandshakes: 256})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestLookupDelay(t *testing.T) {
	if d := lookupDelay(10*time.Minute, 0); d != 10*time.Minute {
		t.Fatalf("no jitter: %v", d)
	}
	if d := lookupDelay(10*time.Minute, 0.999999); d < 10*time.Minute || d >= 12*time.Minute || d < 11*time.Minute+59*time.Second {
		t.Fatalf("most jitter: %v, want just under 12m", d)
	}
}

func TestNewErrors(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 5*time.Second)
	if _, err := New(ctx, "127.0.0.1:0", nil, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil identity: %v", err)
	}
	if _, err := New(ctx, "127.0.0.1:0", &koloid.Identity{}, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("zero identity: %v", err)
	}
	_, err := New(ctx, "127.0.0.1:0", ident(t), &Config{DHT: &kolodht.Config{RequestTimeout: time.Nanosecond}})
	if !errors.Is(err, ErrInvalidConfig) || !errors.Is(err, kolodht.ErrInvalidConfig) {
		t.Fatalf("kolo-dht config error: %v", err)
	}
	tiny := &Config{DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{MaxMemory: 64 << 20}}}}
	if _, err := New(ctx, "127.0.0.1:0", ident(t), tiny); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("a MaxMemory that leaves no place: %v", err)
	}
}

func TestJoinErrors(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	cfg := fastConfig()
	cfg.MaxTopics = 2
	s := newSwarm(t, srv, nil, cfg)
	ctx := testCtx(t, 10*time.Second)
	bad := []*JoinOptions{{}, {Announce: true, MaxPeers: -1}, {Lookup: true, MaxPeers: s.cfg.MaxPeers + 1}}
	for _, o := range bad {
		if err := s.Join(ctx, topicOf("x"), o); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%+v: %v", o, err)
		}
	}
	join(t, s, topicOf("one"), nil)
	if err := s.Join(ctx, topicOf("one"), nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("joined twice: %v", err)
	}
	join(t, s, topicOf("two"), &JoinOptions{Lookup: true})
	if err := s.Join(ctx, topicOf("three"), nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("past MaxTopics: %v", err)
	}
	s.Leave(topicOf("one"))
	join(t, s, topicOf("three"), nil)
	// Without a server, announcing fails with kolo-dht's error, and the topic is not joined.
	lone := newSwarm(t, nil, nil, nil)
	if err := lone.Join(ctx, topicOf("one"), nil); !errors.Is(err, kolodht.ErrNoNodes) {
		t.Fatalf("Join without servers: %v", err)
	}
	if err := lone.Join(ctx, topicOf("one"), &JoinOptions{Lookup: true}); err != nil {
		t.Fatalf("lookup-only Join after a failed one: %v", err)
	}
}

func TestContextCanceled(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	s := newSwarm(t, srv, nil, nil)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Join(canceled, topicOf("c"), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Join: %v", err)
	}
	if _, err := s.Next(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Next: %v", err)
	}
	if err := s.Bootstrap(canceled, []netip.AddrPort{addrOf(srv.Addr())}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Bootstrap: %v", err)
	}
	short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	start := time.Now()
	if _, err := s.Next(short); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("Next with a deadline: %v after %v", err, time.Since(start))
	}
	// Join's announce stops with its context: the only server in the table has gone, and requests wait 5s each.
	gone := newServer(t)
	cfg := fastConfig()
	cfg.DHT.RequestTimeout = 5 * time.Second
	m := newSwarm(t, gone, nil, cfg)
	gone.Close()
	slow, cancel3 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel3()
	start = time.Now()
	err := m.Join(slow, topicOf("slow"), nil)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Join took %v after its context ended", took)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Join with a deadline: %v", err)
	}
}

func TestClosed(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	s := newSwarm(t, srv, nil, nil)
	join(t, s, topicOf("closed"), nil)
	ctx := testCtx(t, 5*time.Second)
	nextErr := make(chan error, 1)
	go func() {
		_, err := s.Next(ctx)
		nextErr <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-nextErr; !errors.Is(err, ErrClosed) {
		t.Fatalf("blocked Next: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := s.Next(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("Next: %v", err)
	}
	if err := s.Join(ctx, topicOf("after"), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Join: %v", err)
	}
	if err := s.Bootstrap(ctx, []netip.AddrPort{addrOf(srv.Addr())}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Bootstrap: %v", err)
	}
	c := newFake(ident(t).PublicKey())
	if err := s.Attach(ctx, c, true); !errors.Is(err, ErrClosed) || c.ctx.Err() == nil {
		t.Fatalf("Attach: %v", err)
	}
	s.Leave(topicOf("closed"))
}

func TestCloseDuringWork(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("busy")
	var peers []*Swarm
	for range 4 {
		p := newSwarm(t, srv, nil, nil)
		join(t, p, topic, nil)
		peers = append(peers, p)
	}
	gone := newSwarm(t, srv, nil, nil)
	join(t, gone, topic, &JoinOptions{Announce: true})
	gone.Close()
	s := newSwarm(t, srv, nil, nil)
	join(t, s, topic, nil)
	ctx := testCtx(t, 10*time.Second)
	go s.Attach(ctx, newFake(ident(t).PublicKey()), false)
	time.Sleep(150 * time.Millisecond)
	start := time.Now()
	s.Close()
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("Close took %v", took)
	}
	for _, p := range peers {
		p.Close()
	}
}

func TestErrorsHaveNoPeerContent(t *testing.T) {
	checkGoroutines(t)
	s, _, topic := helloSwarm(t, nil)
	var errs []error
	big := sides(t, s, true)
	errs = append(errs, s.Attach(testCtx(t, 5*time.Second), relayedFake(t, big, codeRefused), true))
	errs = append(errs, s.Attach(testCtx(t, 5*time.Second), relayedFake(t, big, codeDuplicate), true))
	errs = append(errs, s.Attach(testCtx(t, 5*time.Second), relayedFake(t, big, 77), true))
	ctx := testCtx(t, 5*time.Second)
	errs = append(errs, s.Join(ctx, topic, nil), s.Join(ctx, topic, &JoinOptions{}))
	_, err := New(ctx, "127.0.0.1:0", ident(t), &Config{DHT: &kolodht.Config{RequestTimeout: time.Nanosecond}})
	errs = append(errs, err)
	secrets := []string{hex.EncodeToString(big.PublicKey()), string(big.PublicKey()), "127.0.0.1", hex.EncodeToString(topic[:])}
	for _, err := range errs {
		if err == nil {
			t.Fatal("expected an error")
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, "koloswarm:") {
			t.Errorf("error %q does not start with koloswarm:", msg)
		}
		for _, sec := range secrets {
			if strings.Contains(msg, sec) {
				t.Errorf("error %q contains peer content", msg)
			}
		}
	}
	for _, e := range errs[:3] {
		if !errors.Is(e, ErrRefused) && !errors.Is(e, ErrDuplicate) && !errors.Is(e, ErrProtocol) {
			t.Errorf("Attach error %v is not a sentinel", e)
		}
	}
}

// relayedFake is a Conn from id whose peer closes it with code as soon as the hello starts.
func relayedFake(t *testing.T, id *koloid.Identity, code uint64) Conn {
	f := newFake(id.PublicKey())
	go func() {
		time.Sleep(20 * time.Millisecond)
		f.peerClose(code)
	}()
	return f
}
