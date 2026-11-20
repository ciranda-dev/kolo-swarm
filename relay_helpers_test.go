package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
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

// testRelay is a kolo-relay server on loopback.
type testRelay struct {
	srv  *kolorelay.Server
	key  ed25519.PublicKey
	addr string
}

// loopRelaySecure is a relay listener for tests: every client is 127.0.0.1, so the per-address limit is raised.
func loopRelaySecure() *kolosecure.Config {
	return &kolosecure.Config{Transport: &kolotransport.Config{MaxConns: 256, MaxConnsPerIP: 256, MaxDialed: 1}}
}

// startRelay starts a relay with cfg; a nil cfg.Secure gets the raised listener.
func startRelay(t *testing.T, cfg *kolorelay.ServerConfig) *testRelay {
	t.Helper()
	if cfg == nil {
		cfg = &kolorelay.ServerConfig{}
	}
	if cfg.Secure == nil {
		cfg.Secure = loopRelaySecure()
	}
	return listenRelay(t, cfg)
}

func listenRelay(t *testing.T, cfg *kolorelay.ServerConfig) *testRelay {
	t.Helper()
	return listenRelayAs(t, ident(t), cfg)
}

func listenRelayAs(t *testing.T, id *koloid.Identity, cfg *kolorelay.ServerConfig) *testRelay {
	t.Helper()
	srv, err := kolorelay.Listen(context.Background(), "127.0.0.1:0", id, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return &testRelay{srv: srv, key: id.PublicKey(), addr: srv.Addr().String()}
}

func (r *testRelay) entry() Relay { return Relay{Addr: r.addr, PublicKey: r.key} }

// downRelay is a listed relay that reads every packet and never answers.
func downRelay(t *testing.T) Relay {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		pc.Close()
		<-done
	})
	return Relay{Addr: pc.LocalAddr().String(), PublicKey: ident(t).PublicKey()}
}

// relayConfig returns fastConfig listing relays in order.
func relayConfig(relays ...Relay) *Config {
	c := fastConfig()
	c.Relays = relays
	return c
}

// gate replaces a swarm's kolo-dht Connect: a rule per remote key fails, holds or passes each call.
type gate struct {
	s      *Swarm
	mu     sync.Mutex
	rules  map[string]func(context.Context) error
	calls  map[string]int
	passed map[string]int
}

func newGate(s *Swarm) *gate {
	g := &gate{s: s, rules: map[string]func(context.Context) error{}, calls: map[string]int{}, passed: map[string]int{}}
	s.mu.Lock()
	s.hooks.connect = g.connect
	s.mu.Unlock()
	return g
}

func (g *gate) set(k ed25519.PublicKey, rule func(context.Context) error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rules[string(k)] = rule
}

func (g *gate) connect(ctx context.Context, rec kolodht.Record) (*kolosecure.Conn, error) {
	k := string(rec.PublicKey)
	g.mu.Lock()
	g.calls[k]++
	rule := g.rules[k]
	g.mu.Unlock()
	if rule != nil {
		if err := rule(ctx); err != nil {
			return nil, err
		}
	}
	c, err := g.s.node.Connect(ctx, rec)
	if err == nil {
		g.mu.Lock()
		g.passed[k]++
		g.mu.Unlock()
	}
	return c, err
}

func (g *gate) count(k ed25519.PublicKey) (calls, passed int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls[string(k)], g.passed[string(k)]
}

func refuseConn(context.Context) error { return kolodht.ErrUnreachable }

func holdCtx(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// holdUntil holds a Connect until ch is closed, then lets it pass.
func holdUntil(ch <-chan struct{}) func(context.Context) error {
	return func(ctx context.Context) error {
		select {
		case <-ch:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// relayLog records the relay dials of a swarm in order; hold, if set, runs in each.
type relayLog struct {
	mu    sync.Mutex
	dials [][2]string // relay key, target key
	hold  func(ctx context.Context, relay, target ed25519.PublicKey)
}

func logRelays(s *Swarm, hold func(ctx context.Context, relay, target ed25519.PublicKey)) *relayLog {
	l := &relayLog{hold: hold}
	s.mu.Lock()
	s.hooks.beforeRelay = func(ctx context.Context, relay, target ed25519.PublicKey) {
		l.mu.Lock()
		l.dials = append(l.dials, [2]string{string(relay), string(target)})
		l.mu.Unlock()
		if l.hold != nil {
			l.hold(ctx, relay, target)
		}
	}
	s.mu.Unlock()
	return l
}

func (l *relayLog) to(target ed25519.PublicKey) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, d := range l.dials {
		if d[1] == string(target) {
			out = append(out, d[0])
		}
	}
	return out
}

func (l *relayLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.dials)
}

// relayEvents returns the errors of the RelayChanged events w saw for relay, in order.
func (w *watcher) relayEvents(relay ed25519.PublicKey) []error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []error
	for _, e := range w.events {
		if e.Kind == RelayChanged && bytes.Equal(e.PublicKey, relay) {
			out = append(out, e.Err)
		}
	}
	return out
}

// held reports whether the newest RelayChanged w saw for relay says the reservation is held.
func (w *watcher) held(relay ed25519.PublicKey) bool {
	ev := w.relayEvents(relay)
	return len(ev) > 0 && ev[len(ev)-1] == nil
}

// sawRelay reports whether w saw a RelayChanged for relay with err.
func (w *watcher) sawRelay(relay ed25519.PublicKey, err error) bool {
	for _, e := range w.relayEvents(relay) {
		if errors.Is(e, err) {
			return true
		}
	}
	return false
}

func relayOf(p *Peer) ed25519.PublicKey {
	if p == nil {
		return nil
	}
	return relayKeyOf(p.Conn())
}

// waitRelayed waits for w's peer k to be relayed, through relay if not nil.
func waitRelayed(t *testing.T, w *watcher, k, relay ed25519.PublicKey) *Peer {
	t.Helper()
	var p *Peer
	waitFor(t, 60*time.Second, "a relayed peer", func() bool {
		p = w.peer(k)
		return p != nil && !p.Direct() && (relay == nil || bytes.Equal(relayOf(p), relay))
	})
	return p
}

func waitDirect(t *testing.T, w *watcher, k ed25519.PublicKey) *Peer {
	t.Helper()
	var p *Peer
	waitFor(t, 60*time.Second, "a direct peer", func() bool {
		p = w.peer(k)
		return p != nil && p.Direct()
	})
	return p
}

// rawDial dials target through relay with a new identity and closes the connection; it returns Dial's error.
func rawDial(t *testing.T, relay Relay, target ed25519.PublicKey) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := kolorelay.Dial(ctx, relay.Addr, relay.PublicKey, ident(t), target, nil)
	if err == nil {
		c.Close()
	}
	return err
}

// drained pops every event queued in s. Every event is queued with mu held, so holding it reads the queue whole; s must
// have no watcher.
func drained(s *Swarm) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		ev, err := s.events.Pop(ctx, nil)
		cancel()
		if err != nil {
			return out
		}
		out = append(out, ev)
	}
}

func unreachableFor(evs []Event, k ed25519.PublicKey) bool {
	for _, e := range evs {
		if e.Kind == Unreachable && bytes.Equal(e.PublicKey, k) {
			return true
		}
	}
	return false
}

// pathsDone reports whether no dial path goroutine runs in the process.
func pathsDone() bool {
	for _, st := range goroutines() {
		if strings.Contains(st, "kolo-swarm.(*Swarm).dialVia(") || strings.Contains(st, "kolo-swarm.(*Swarm).relayChain(") {
			return false
		}
	}
	return true
}

// viaRelay is a test double of a relayed connection: no RemoteAddr, and the key of the relay it came through.
type viaRelay struct {
	Conn
	relay ed25519.PublicKey
}

func (v viaRelay) RelayPublicKey() ed25519.PublicKey { return bytes.Clone(v.relay) }

// keyed reports another remote key than its Conn's.
type keyed struct {
	viaRelay
	key ed25519.PublicKey
}

func (k keyed) RemotePublicKey() ed25519.PublicKey { return k.key }

// feed replaces s's reservation Accept with the connections sent on the returned channel.
func feed(s *Swarm) chan Conn {
	ch := make(chan Conn)
	s.mu.Lock()
	s.hooks.accept = func(ctx context.Context, _ *kolorelay.Reservation) (Conn, error) {
		select {
		case c := <-ch:
			return c, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.mu.Unlock()
	return ch
}

// fedPair returns a kolo-secure connection between a and x as a's relayed side through relay, and x's side.
func fedPair(t *testing.T, a, x *koloid.Identity, relay ed25519.PublicKey) (Conn, *kolosecure.Conn) {
	t.Helper()
	cx, ca := securePair(t, x, a)
	return viaRelay{Conn: ca, relay: relay}, cx
}

// udpProxy forwards UDP between its clients and one address, one upstream socket per client, until drop is set.
type udpProxy struct {
	pc   *net.UDPConn
	to   *net.UDPAddr
	drop atomic.Bool
	mu   sync.Mutex
	ups  map[string]*net.UDPConn
	wg   sync.WaitGroup
}

func startProxy(t *testing.T, to string) *udpProxy {
	t.Helper()
	ta, err := net.ResolveUDPAddr("udp4", to)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &udpProxy{pc: pc, to: ta, ups: map[string]*net.UDPConn{}}
	p.wg.Go(p.loop)
	t.Cleanup(func() {
		pc.Close()
		p.mu.Lock()
		for _, u := range p.ups {
			u.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func (p *udpProxy) addr() string { return p.pc.LocalAddr().String() }

func (p *udpProxy) loop() {
	buf := make([]byte, 2048)
	for {
		n, from, err := p.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if p.drop.Load() {
			continue
		}
		p.mu.Lock()
		up := p.ups[from.String()]
		if up == nil {
			if up, err = net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, p.to); err != nil {
				p.mu.Unlock()
				continue
			}
			p.ups[from.String()] = up
			p.wg.Go(func() { p.back(up, from) })
		}
		p.mu.Unlock()
		up.Write(buf[:n])
	}
}

func (p *udpProxy) back(up *net.UDPConn, client *net.UDPAddr) {
	buf := make([]byte, 2048)
	for {
		n, err := up.Read(buf)
		if err != nil {
			return
		}
		if !p.drop.Load() {
			p.pc.WriteToUDP(buf[:n], client)
		}
	}
}
