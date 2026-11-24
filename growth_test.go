package koloswarm

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// growthDelay is the one-way delay of the growth tests: at a 50 ms round trip the auto-tuning needs a reader of only
// about 5 MB/s to double a 1 MiB window, well under what loopback gives.
const growthDelay = 25 * time.Millisecond

// growthTransport is the setting the guide recommends: growth on, and a connection window equal to the stream window, so
// a connection nobody marked keeps exactly the initial windows.
func growthTransport() *kolotransport.Config {
	tc := loopTransport()
	tc.WindowGrowth = true
	tc.MaxStreamReceiveWindow = 256 << 10
	tc.MaxConnReceiveWindow = 256 << 10
	return tc
}

func growthConfig(allow func(ed25519.PublicKey, netip.AddrPort) bool) *Config {
	cfg := fastConfig()
	cfg.DHT.Secure.Transport = growthTransport()
	cfg.Allow = allow
	return cfg
}

func only(k ed25519.PublicKey) func(ed25519.PublicKey, netip.AddrPort) bool {
	return func(got ed25519.PublicKey, _ netip.AddrPort) bool { return string(got) == string(k) }
}

// delayLink relays UDP from a loopback socket to target with a fixed one-way delay each way, so every test sees the same
// round trip. A window grows only when it is read faster than a few round trips, and plain loopback has none to speak of.
func delayLink(t *testing.T, target string, oneWay time.Duration) string {
	t.Helper()
	dst, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	type packet struct {
		from *net.UDPAddr
		data []byte
		at   time.Time
	}
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		closed bool
		up     = map[string]*net.UDPConn{}
		upQ    = make(chan packet, 8192)
		downQ  = make(chan packet, 8192)
		done   = make(chan struct{})
	)
	push := func(q chan packet, p packet) {
		p.at = time.Now().Add(oneWay)
		select {
		case q <- p:
		default:
		}
	}
	drain := func(q chan packet, send func(packet)) {
		defer wg.Done()
		for {
			select {
			case p := <-q:
				select {
				case <-time.After(time.Until(p.at)):
					send(p)
				case <-done:
					return
				}
			case <-done:
				return
			}
		}
	}
	upstream := func(from *net.UDPAddr) *net.UDPConn {
		mu.Lock()
		defer mu.Unlock()
		if c := up[from.String()]; c != nil || closed {
			return c
		}
		c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dst)
		if err != nil {
			return nil
		}
		up[from.String()] = c
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				push(downQ, packet{from: from, data: append([]byte(nil), buf[:n]...)})
			}
		}()
		return c
	}
	wg.Add(3)
	go drain(upQ, func(p packet) {
		if c := upstream(p.from); c != nil {
			c.Write(p.data)
		}
	})
	go drain(downQ, func(p packet) { front.WriteToUDP(p.data, p.from) })
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, from, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			upstream(from)
			push(upQ, packet{from: from, data: append([]byte(nil), buf[:n]...)})
		}
	}()
	t.Cleanup(func() {
		close(done)
		front.Close()
		mu.Lock()
		closed = true
		for _, c := range up {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return front.LocalAddr().String()
}

// pump sends size bytes from sender on a new stream and has receiver read them all at once, the traffic that makes a
// trusted connection's windows grow.
func pump(t *testing.T, sender, receiver Conn, size int) {
	t.Helper()
	ctx := testCtx(t, 20*time.Second)
	st, err := sender.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 64<<10)
		for left := size; left > 0; left -= len(buf) {
			if _, err := st.Write(buf[:min(len(buf), left)]); err != nil {
				return
			}
		}
		st.Close()
	}()
	rs, err := receiver.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := io.Copy(io.Discard, rs); err != nil || int(n) != size {
		t.Fatalf("read %d of %d bytes: %v", n, size, err)
	}
}

// credit is how many bytes writer can put into its peer's connection while the peer reads nothing.
func credit(t *testing.T, writer Conn) int {
	t.Helper()
	n, streams := probe(t, writer)
	for _, w := range streams {
		w.Close()
	}
	return n
}

// probe writes on six streams at once, each with its own credit, until the peer's connection window blocks them, and
// returns what they took and the open streams.
func probe(t *testing.T, writer Conn) (int, []*kolotransport.Stream) {
	t.Helper()
	ctx := testCtx(t, 20*time.Second)
	var streams []*kolotransport.Stream
	for range 6 {
		w, err := writer.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, w)
	}
	var sent atomic.Int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(time.Second)
	for _, w := range streams {
		wg.Go(func() {
			w.SetWriteDeadline(deadline)
			n, err := w.Write(make([]byte, 1<<20))
			if err != os.ErrDeadlineExceeded {
				t.Errorf("write: %v", err)
			}
			sent.Add(int64(n))
		})
	}
	wg.Wait()
	return int(sent.Load()), streams
}

// growWait bounds how long a test waits for a window to grow. quic-go doubles a window only when the reader consumes it
// within about three round trips, which a busy machine can delay but not prevent.
const growWait = 60 * time.Second

// growCredit pumps from sender to receiver and measures sender's credit after each round until it is above min or
// growWait has passed. A window never shrinks, so a slow round only costs another round; the probe's streams are read
// to the end first so they do not hold the window.
func growCredit(t *testing.T, sender, receiver Conn, min int) int {
	t.Helper()
	deadline := time.Now().Add(growWait)
	for {
		pump(t, sender, receiver, 8<<20)
		n, streams := probe(t, sender)
		for _, w := range streams {
			w.Close()
		}
		if n > min || !time.Now().Before(deadline) {
			return n
		}
		ctx := testCtx(t, 20*time.Second)
		for range streams {
			rs, err := receiver.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, rs)
		}
	}
}

var growthTopic = topicOf("growth")

// newHub starts a swarm that announces growthTopic and so only accepts: peers find it but are told not to dial it.
func newHub(t *testing.T, srv *kolodht.Node, id *koloid.Identity, cfg *Config) (*Swarm, *watcher) {
	t.Helper()
	hub := newSwarm(t, srv, id, cfg)
	wh := watch(t, hub)
	join(t, hub, growthTopic, &JoinOptions{Announce: true})
	return hub, wh
}

// newPeer starts a swarm that looks up growthTopic and has found hub, whose DHT address its Allow refuses, so the
// swarm never dials it and the test attaches the connection it makes.
func newPeer(t *testing.T, srv *kolodht.Node, hub *Swarm, id *koloid.Identity) *Swarm {
	t.Helper()
	cfg := fastConfig()
	cfg.Allow = func(_ ed25519.PublicKey, addr netip.AddrPort) bool { return addr != addrOf(hub.Addr()) }
	peer := newSwarm(t, srv, id, cfg)
	w := watch(t, peer)
	join(t, peer, growthTopic, &JoinOptions{Lookup: true})
	waitFor(t, 10*time.Second, "the peer found the hub", func() bool { return w.kinds(Found) > 0 })
	return peer
}

// reach attaches a connection from peer, made through a delayed link to hub's own socket, and returns it with the
// connection hub holds for it once hub's swarm admitted it.
func reach(t *testing.T, hub, peer *Swarm, wh *watcher, id *koloid.Identity) (mine, theirs Conn) {
	t.Helper()
	ctx := testCtx(t, 20*time.Second)
	c, err := kolosecure.Dial(ctx, delayLink(t, hub.Addr().String(), growthDelay), id, hub.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := peer.Attach(ctx, c, true); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	waitFor(t, 10*time.Second, "hub admitted the peer", func() bool { return wh.peer(id.PublicKey()) != nil })
	return c, wh.peer(id.PublicKey()).Conn()
}

// An accepted connection of a key Allow admitted grows its window under fast reading; one of a swarm with no Allow
// never does, because there is no trust decision.
func TestGrowthAcceptedPath(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	for _, tt := range []struct {
		name  string
		allow bool
		grows bool
	}{{"admitted by Allow", true, true}, {"no Allow", false, false}} {
		t.Run(tt.name, func(t *testing.T) {
			checkGoroutines(t)
			ids, ida := ident(t), ident(t)
			var allow func(ed25519.PublicKey, netip.AddrPort) bool
			if tt.allow {
				allow = only(ida.PublicKey())
			}
			srv := newServer(t)
			hub, wh := newHub(t, srv, ids, growthConfig(allow))
			peer := newPeer(t, srv, hub, ida)
			if tt.allow {
				// A key Allow refuses is closed with the refused code and never becomes a peer.
				idq := ident(t)
				q := newPeer(t, srv, hub, idq)
				c, err := kolosecure.Dial(testCtx(t, 10*time.Second), delayLink(t, hub.Addr().String(), growthDelay), idq, hub.PublicKey(), nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				if err := q.Attach(testCtx(t, 10*time.Second), c, true); err == nil {
					t.Fatal("the refused key was admitted")
				}
				if wh.peer(idq.PublicKey()) != nil {
					t.Fatal("the refused key is a peer")
				}
			}
			mine, theirs := reach(t, hub, peer, wh, ida)
			if _, ok := theirs.(*kolosecure.Conn); !ok {
				t.Fatalf("hub's connection is a %T, want the accepted *kolosecure.Conn", theirs)
			}
			if tt.grows {
				if n := growCredit(t, mine, theirs, 1<<20); n <= 1<<20 {
					t.Fatalf("the admitted connection took only %d bytes: its window did not grow", n)
				}
				return
			}
			pump(t, mine, theirs, 8<<20)
			if n := credit(t, mine); n > 256<<10 {
				t.Fatalf("a connection nobody marked took %d bytes into a 256 KiB window", n)
			}
		})
	}
}

// A connection the swarm dialed to a key Allow admitted grows too.
func TestGrowthDialedPath(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("growth dialed")
	ids, ida := ident(t), ident(t)
	cfg := growthConfig(only(ida.PublicKey()))
	hub := newSwarm(t, srv, ids, cfg)
	wh := watch(t, hub)
	peer := newSwarm(t, srv, ida, nil)
	wp := watch(t, peer)
	link := delayLink(t, peer.Addr().String(), growthDelay)
	var dialed atomic.Int64
	hub.mu.Lock()
	hub.hooks.connect = func(ctx context.Context, rec kolodht.Record) (*kolosecure.Conn, error) {
		dialed.Add(1)
		return kolosecure.Dial(ctx, link, ids, rec.PublicKey, &kolosecure.Config{Transport: growthTransport()})
	}
	hub.mu.Unlock()
	join(t, peer, topic, &JoinOptions{Announce: true})
	join(t, hub, topic, &JoinOptions{Lookup: true})
	waitFor(t, 15*time.Second, "peers connected", func() bool { return wh.peer(ida.PublicKey()) != nil && wp.peer(ids.PublicKey()) != nil })
	if dialed.Load() == 0 || !wh.peer(ida.PublicKey()).Direct() {
		t.Fatal("hub did not dial the peer")
	}
	mine, theirs := wp.peer(ids.PublicKey()).Conn(), wh.peer(ida.PublicKey()).Conn()
	if n := growCredit(t, mine, theirs, 1<<20); n <= 1<<20 {
		t.Fatalf("the dialed connection took only %d bytes: its window did not grow", n)
	}
}

// With the default config nothing grows.
func TestGrowthOffByDefault(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	c, err := (*Config)(nil).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if tc := c.DHT.Secure.Transport; tc.WindowGrowth || tc.MaxMemory != kolotransport.DefaultMaxMemory {
		t.Fatalf("default transport config %+v", tc)
	}
	ids, ida := ident(t), ident(t)
	cfg := fastConfig()
	cfg.Allow = only(ida.PublicKey())
	srv := newServer(t)
	hub, wh := newHub(t, srv, ids, cfg)
	peer := newPeer(t, srv, hub, ida)
	mine, theirs := reach(t, hub, peer, wh, ida)
	pump(t, mine, theirs, 8<<20)
	if n := credit(t, mine); n > 512<<10 {
		t.Fatalf("a connection took %d bytes into a 512 KiB window with growth off", n)
	}
}

// spy is a Conn that counts AllowWindowGrowth calls.
type spy struct {
	Conn
	marked atomic.Int64
}

func (s *spy) AllowWindowGrowth() bool { s.marked.Add(1); return true }

// A connection Allow refuses, or one the swarm does not admit for another reason, is never marked; an admitted one is
// marked once, and with no Allow nothing is marked.
func TestGrowthMarksOnlyAdmitted(t *testing.T) {
	checkGoroutines(t)
	// attachSpy attaches to hub a connection from a new peer, seen through a spy, and returns Attach's error.
	attachSpy := func(t *testing.T, srv *kolodht.Node, hub *Swarm, hubID, id *koloid.Identity) (*spy, error) {
		t.Helper()
		peer := newPeer(t, srv, hub, id)
		ca, cb := securePair(t, id, hubID)
		sp := &spy{Conn: cb}
		ctx := testCtx(t, 10*time.Second)
		errc := make(chan error, 1)
		go func() { errc <- peer.Attach(ctx, ca, true) }()
		err := hub.Attach(ctx, sp, false)
		<-errc
		return sp, err
	}
	setup := func(t *testing.T, cfg *Config) (*kolodht.Node, *Swarm, *koloid.Identity) {
		srv, ids := newServer(t), ident(t)
		hub, _ := newHub(t, srv, ids, cfg)
		return srv, hub, ids
	}
	t.Run("admitted", func(t *testing.T) {
		ida := ident(t)
		srv, hub, ids := setup(t, growthConfig(only(ida.PublicKey())))
		sp, err := attachSpy(t, srv, hub, ids, ida)
		if err != nil || sp.marked.Load() != 1 {
			t.Fatalf("Attach: %v, marked %d times, want nil and 1", err, sp.marked.Load())
		}
	})
	t.Run("refused by Allow", func(t *testing.T) {
		srv, hub, ids := setup(t, growthConfig(only(ident(t).PublicKey())))
		sp, err := attachSpy(t, srv, hub, ids, ident(t))
		if err == nil || sp.marked.Load() != 0 {
			t.Fatalf("Attach: %v, marked %d times, want an error and 0", err, sp.marked.Load())
		}
	})
	t.Run("no Allow", func(t *testing.T) {
		srv, hub, ids := setup(t, growthConfig(nil))
		sp, err := attachSpy(t, srv, hub, ids, ident(t))
		if err != nil || sp.marked.Load() != 0 {
			t.Fatalf("Attach: %v, marked %d times, want nil and 0", err, sp.marked.Load())
		}
	})
	t.Run("allowed but swarm full", func(t *testing.T) {
		cfg := growthConfig(func(ed25519.PublicKey, netip.AddrPort) bool { return true })
		cfg.MaxPeers = 1
		srv, hub, ids := setup(t, cfg)
		if sp, err := attachSpy(t, srv, hub, ids, ident(t)); err != nil || sp.marked.Load() != 1 {
			t.Fatalf("first Attach: %v, marked %d times", err, sp.marked.Load())
		}
		if sp, err := attachSpy(t, srv, hub, ids, ident(t)); err == nil || sp.marked.Load() != 0 {
			t.Fatalf("second Attach: %v, marked %d times, want an error and 0", err, sp.marked.Load())
		}
	})
}

// A panicking Allow refuses, so nothing is marked.
func TestGrowthPanickingAllow(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	ids, id := ident(t), ident(t)
	hub, _ := newHub(t, srv, ids, growthConfig(func(ed25519.PublicKey, netip.AddrPort) bool { panic("app bug") }))
	peer := newPeer(t, srv, hub, id)
	ca, cb := securePair(t, id, ids)
	sp := &spy{Conn: cb}
	ctx := testCtx(t, 10*time.Second)
	go peer.Attach(ctx, ca, true)
	if err := hub.Attach(ctx, sp, false); err == nil || sp.marked.Load() != 0 {
		t.Fatalf("Attach: %v, marked %d times", err, sp.marked.Load())
	}
}

// A relayed Conn has no AllowWindowGrowth, so admitting it works and nothing is marked.
func TestGrowthRelayedConnIsSkipped(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	ids, ida := ident(t), ident(t)
	hub, wh := newHub(t, srv, ids, growthConfig(only(ida.PublicKey())))
	peer := newPeer(t, srv, hub, ida)
	ca, cb := securePair(t, ida, ids)
	ctx := testCtx(t, 10*time.Second)
	go peer.Attach(ctx, relayed{ca}, true)
	if err := hub.Attach(ctx, relayed{cb}, false); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	waitFor(t, 5*time.Second, "peer", func() bool { return wh.peer(ida.PublicKey()) != nil })
}

// With growth on, the swarm's derived kolo-transport limits pass kolo-transport's own check at any MaxPeers and window,
// and the growth it allows is part of MaxMemory.
func TestGrowthConfigDerivedLimits(t *testing.T) {
	checkGoroutines(t)
	for _, tt := range []struct {
		name  string
		peers int
		tc    kolotransport.Config
	}{
		{"defaults", 0, kolotransport.Config{WindowGrowth: true}},
		{"largest swarm", 1024, kolotransport.Config{WindowGrowth: true}},
		{"larger windows", 1024, kolotransport.Config{WindowGrowth: true, MaxStreamReceiveWindow: 1 << 20, MaxConnReceiveWindow: 1 << 20}},
		{"larger grown memory", 1024, kolotransport.Config{WindowGrowth: true, MaxGrownMemory: 4 << 30}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := tt.tc
			cfg := Config{MaxPeers: tt.peers, DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: &tc}}}
			c, err := cfg.withDefaults()
			if err != nil {
				t.Fatal(err)
			}
			got := c.DHT.Secure.Transport
			conns := int64(got.MaxConns + got.MaxDialed)
			win := cmp.Or(tc.MaxConnReceiveWindow, kolotransport.DefaultMaxConnReceiveWindow)
			grown := cmp.Or(tc.MaxGrownMemory, kolotransport.DefaultMaxGrownMemory)
			if want := max(kolotransport.DefaultMaxMemory, conns*win+grown); got.MaxMemory != want {
				t.Fatalf("MaxMemory %d, want %d", got.MaxMemory, want)
			}
			l, err := kolotransport.Listen(testCtx(t, 10*time.Second), "127.0.0.1:0", got)
			if err != nil {
				t.Fatalf("kolo-transport refused the derived config: %v", err)
			}
			l.Close()
		})
	}
}

// A MaxMemory the caller sets is kept as it is.
func TestGrowthConfigKeepsExplicitAndOldDerivation(t *testing.T) {
	cfg := Config{DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{WindowGrowth: true, MaxMemory: 3 << 30}}}}
	c, err := cfg.withDefaults()
	if err != nil || c.DHT.Secure.Transport.MaxMemory != 3<<30 {
		t.Fatalf("explicit MaxMemory: %v, %d", err, c.DHT.Secure.Transport.MaxMemory)
	}
	cfg = Config{MaxPeers: 1024, DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{MaxConnReceiveWindow: 1 << 20}}}}
	c, err = cfg.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	tc := c.DHT.Secure.Transport
	if want := int64(tc.MaxConns+tc.MaxDialed) << 20; tc.MaxMemory != want {
		t.Fatalf("MaxMemory %d without growth, want %d", tc.MaxMemory, want)
	}
}

// With Datagrams on, the derived places and MaxMemory count kolo-transport's 240 KiB of datagram queues per connection,
// so the derived config passes kolo-transport's own check.
func TestDatagramsConfigDerivedLimits(t *testing.T) {
	checkGoroutines(t)
	for _, tt := range []struct {
		name  string
		peers int
		tc    kolotransport.Config
	}{
		{"defaults", 0, kolotransport.Config{Datagrams: true}},
		{"window growth", 0, kolotransport.Config{Datagrams: true, WindowGrowth: true}},
		{"set MaxPeers", 1024, kolotransport.Config{Datagrams: true}},
		{"set MaxPeers and growth", 1024, kolotransport.Config{Datagrams: true, WindowGrowth: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := tt.tc
			c, err := (&Config{MaxPeers: tt.peers, DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: &tc}}}).withDefaults()
			if err != nil {
				t.Fatal(err)
			}
			got := c.DHT.Secure.Transport
			l, err := kolotransport.Listen(testCtx(t, 10*time.Second), "127.0.0.1:0", got)
			if err != nil {
				t.Fatalf("kolo-transport refused the derived config: %v", err)
			}
			l.Close()
		})
	}
	c, err := (&Config{DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{Datagrams: true}}}}).withDefaults()
	if tr := c.DHT.Secure.Transport; err != nil || c.MaxPeers != 822 || c.MaxInbound != 411 || tr.MaxDialed != 902 || tr.MaxConns != 491 || tr.MaxMemory != kolotransport.DefaultMaxMemory {
		t.Fatalf("derived with Datagrams: %v, MaxPeers %d, MaxInbound %d, %+v", err, c.MaxPeers, c.MaxInbound, tr)
	}
}
