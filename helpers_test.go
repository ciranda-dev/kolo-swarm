package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// checkGoroutines fails the test if goroutines started during it outlive its cleanups.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := make(map[string]string)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}

func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func ident(t testing.TB) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// identPair returns two identities, the first with the smaller public key.
func identPair(t testing.TB) (small, large *koloid.Identity) {
	a, b := ident(t), ident(t)
	if bytes.Compare(a.PublicKey(), b.PublicKey()) > 0 {
		a, b = b, a
	}
	return a, b
}

func topicOf(name string) Topic { return Topic(sha256.Sum256([]byte(name))) }

func addrOf(a net.Addr) netip.AddrPort {
	ap := a.(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// loopTransport lets many loopback peers, which share one source IP, connect to one node.
func loopTransport() *kolotransport.Config {
	return &kolotransport.Config{MaxConnsPerIP: 64}
}

// newServer starts a kolo-dht server on loopback, with per-IP limits raised because every test peer is 127.0.0.1.
func newServer(t *testing.T) *kolodht.Node {
	t.Helper()
	n, err := kolodht.New(context.Background(), "127.0.0.1:0", ident(t), &kolodht.Config{
		Server:               true,
		RequestTimeout:       300 * time.Millisecond,
		MaxRequestsPerIP:     5000,
		MaxRequestsPerPrefix: 10000,
		MaxRequests:          20000,
		MaxRecordsPerIP:      512,
		MaxRecordsPerTopic:   128,
		MaxRelays:            256,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// fastConfig returns a Config with test timings; edit it before newSwarm.
func fastConfig() *Config {
	return &Config{
		DHT: &kolodht.Config{
			RequestTimeout: 300 * time.Millisecond,
			PunchTimeout:   time.Second,
			Secure:         &kolosecure.Config{Transport: loopTransport()},
		},
		MaxConnecting:      2,
		MaxHandshakesPerIP: 16,
		HelloTimeout:       2 * time.Second,
		LookupInterval:     time.Second,
		RetryMin:           100 * time.Millisecond,
		RetryMax:           time.Second,
	}
}

// newSwarm starts a swarm on loopback as id (a new identity if nil), bootstrapped from srv if not nil.
func newSwarm(t *testing.T, srv *kolodht.Node, id *koloid.Identity, cfg *Config) *Swarm {
	t.Helper()
	if id == nil {
		id = ident(t)
	}
	if cfg == nil {
		cfg = fastConfig()
	}
	s, err := New(context.Background(), "127.0.0.1:0", id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.Bootstrap(ctx, []netip.AddrPort{addrOf(srv.Addr())}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func join(t *testing.T, s *Swarm, topic Topic, opts *JoinOptions) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Join(ctx, topic, opts); err != nil {
		t.Fatal(err)
	}
}

// watcher reads a swarm's events and tracks its current peers.
type watcher struct {
	s      *Swarm
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	events []Event
	peers  map[string]*Peer
	most   int
	change chan struct{}

	lookups atomic.Int64 // lookups the swarm finished, when the test counts them
}

func watch(t *testing.T, s *Swarm) *watcher {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	w := &watcher{s: s, cancel: cancel, done: make(chan struct{}), peers: map[string]*Peer{}, change: make(chan struct{}, 1)}
	go func() {
		defer close(w.done)
		for {
			ev, err := s.Next(ctx)
			if err != nil {
				return
			}
			w.mu.Lock()
			w.events = append(w.events, ev)
			k := string(ev.PublicKey)
			switch ev.Kind {
			case Connected:
				if old := w.peers[k]; old != nil {
					t.Errorf("Connected for a key whose previous peer had no Lost")
				}
				w.peers[k] = ev.Peer
				w.most = max(w.most, len(w.peers))
			case Lost:
				if w.peers[k] == ev.Peer {
					delete(w.peers, k)
				}
			}
			w.mu.Unlock()
			select {
			case w.change <- struct{}{}:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-w.done
	})
	return w
}

func (w *watcher) peer(key ed25519.PublicKey) *Peer {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.peers[string(key)]
}

func (w *watcher) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.peers)
}

func (w *watcher) maxPeers() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.most
}

func (w *watcher) kinds(k EventKind) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, e := range w.events {
		if e.Kind == k {
			n++
		}
	}
	return n
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stable waits until cond has held for hold without a break, within d.
func stable(t *testing.T, d, hold time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	var since time.Time
	for {
		now := time.Now()
		switch {
		case !cond():
			since = time.Time{}
		case since.IsZero():
			since = now
		case now.Sub(since) >= hold:
			return
		}
		if now.After(deadline) {
			t.Fatalf("timed out after %v waiting for %s to hold %v", d, what, hold)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// echoOver proves a and b hold the two ends of one connection: a stream opened on a arrives on b.
func echoOver(t *testing.T, a, b Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		st, err := b.AcceptStream(ctx)
		if err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(st, buf); err != nil {
			errc <- err
			return
		}
		_, err = st.Write(buf)
		st.Close()
		errc <- err
	}()
	st, err := a.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo: %q, %v", buf, err)
	}
	st.Close()
	if err := <-errc; err != nil {
		t.Fatalf("echo side: %v", err)
	}
}

// closeCodeOf waits for c to end and returns the code its peer closed it with.
func closeCodeOf(t *testing.T, c Conn, d time.Duration) uint64 {
	t.Helper()
	select {
	case <-c.Context().Done():
	case <-time.After(d):
		t.Fatalf("connection still open after %v", d)
	}
	var te *kolotransport.Error
	if !errors.As(context.Cause(c.Context()), &te) {
		t.Fatalf("connection ended with %v, no code", context.Cause(c.Context()))
	}
	return te.Code
}

// relayed hides a Conn's RemoteAddr, as a kolo-relay Conn has none: a test double for a relayed connection.
type relayed struct{ Conn }

func (s *Swarm) slotCounts() (total, inbound int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.placesLocked(), s.inbound
}

// dump logs every event w saw, for a failing test.
func (w *watcher) dump(t *testing.T, name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.events {
		extra := ""
		if e.Peer != nil {
			extra = fmt.Sprintf("peer=%p dead=%v", e.Peer, e.Peer.Conn().Context().Err() != nil)
		}
		t.Logf("%s: %v %x %v err=%v %s", name, e.Kind, e.PublicKey[:4], e.Addr, e.Err, extra)
	}
	n, in := w.s.slotCounts()
	t.Logf("%s: slots=%d inbound=%d", name, n, in)
}

var fakeN atomic.Uint32

// fakeAddr returns a new address in the benchmarking range 198.18.0.0/15 for a test record; no test reaches it.
func fakeAddr() netip.AddrPort {
	n := fakeN.Add(1)
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18 + byte(n>>16&1), byte(n >> 8), byte(n)}), 9)
}

// longTest skips a test that needs several seconds of wall time when go test runs with -short.
func longTest(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("takes several seconds; run without -short")
	}
}
