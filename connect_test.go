package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

// TestPeerOutbound checks that the swarm that dialed a key from a lookup reports its peer as outbound, and the swarm
// that accepted it reports inbound.
func TestPeerOutbound(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	a, b := newSwarm(t, srv, nil, nil), newSwarm(t, srv, nil, nil)
	wa, wb := watch(t, a), watch(t, b)
	topic := topicOf("outbound")
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitFor(t, 15*time.Second, "both connected", func() bool {
		return wa.peer(b.PublicKey()) != nil && wb.peer(a.PublicKey()) != nil
	})
	if !wa.peer(b.PublicKey()).Outbound() {
		t.Fatal("dialing side reports an inbound peer")
	}
	if wb.peer(a.PublicKey()).Outbound() {
		t.Fatal("accepting side reports an outbound peer")
	}
}

// TestAttachOutbound checks that Attach's outbound flag is the peer's direction.
func TestAttachOutbound(t *testing.T) {
	checkGoroutines(t)
	a, b, wa, wb, ia, ib := attachPair(t)
	ca, cb := securePair(t, ia, ib)
	if ea, eb := attachBoth(t, a, b, ca, cb); ea != nil || eb != nil {
		t.Fatalf("Attach: %v, %v", ea, eb)
	}
	waitFor(t, 3*time.Second, "both peers", func() bool { return wa.peer(ib.PublicKey()) != nil && wb.peer(ia.PublicKey()) != nil })
	if !wa.peer(ib.PublicKey()).Outbound() || wb.peer(ia.PublicKey()).Outbound() {
		t.Fatal("attached directions wrong")
	}
}

// connectPair returns two swarms without kolo-dht servers, as dialer and target ids, both joined to topic for lookups
// only, so no connection forms unless Connect makes it.
func connectPair(t *testing.T, dialer, target *koloid.Identity, topic Topic) (a, b *Swarm, wa, wb *watcher) {
	t.Helper()
	a, b = newSwarm(t, nil, dialer, nil), newSwarm(t, nil, target, nil)
	wa, wb = watch(t, a), watch(t, b)
	join(t, a, topic, &JoinOptions{Lookup: true})
	join(t, b, topic, &JoinOptions{Lookup: true})
	return a, b, wa, wb
}

func TestConnect(t *testing.T) {
	small, large := identPair(t)
	for _, tc := range []struct {
		name           string
		dialer, target *koloid.Identity
	}{{"dialer arbitrates", small, large}, {"target arbitrates", large, small}} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			topic := topicOf("connect")
			a, b, wa, wb := connectPair(t, tc.dialer, tc.target, topic)
			if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); err != nil {
				t.Fatalf("Connect: %v", err)
			}
			pa := wa.wait(t, b.PublicKey())
			pb := wb.wait(t, a.PublicKey())
			if !pa.Outbound() || pb.Outbound() {
				t.Fatalf("directions: dialer outbound %v, target outbound %v", pa.Outbound(), pb.Outbound())
			}
			if !pa.Direct() || pa.Addr() != addrOf(b.Addr()) {
				t.Fatalf("dialer's peer: direct %v, addr %v", pa.Direct(), pa.Addr())
			}
			for _, p := range []*Peer{pa, pb} {
				if got := p.Topics(); len(got) != 1 || got[0] != topic {
					t.Fatalf("Topics = %x", got)
				}
			}
			echoOver(t, pa.Conn(), pb.Conn())
			if err := a.Connect(testCtx(t, 5*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); !errors.Is(err, ErrDuplicate) {
				t.Fatalf("second Connect: %v", err)
			}
			// The second Connect is refused before any dial, so nothing can change after it.
			if n, _ := a.slotCounts(); n != 1 || wa.peer(b.PublicKey()) != pa || wa.kinds(Lost) != 0 {
				t.Fatalf("after the second Connect: places %d, peer kept %v, Lost %d", n, wa.peer(b.PublicKey()) == pa, wa.kinds(Lost))
			}
		})
	}
}

// wait returns the peer of key once w has it.
func (w *watcher) wait(t *testing.T, key ed25519.PublicKey) *Peer {
	t.Helper()
	waitFor(t, 5*time.Second, "peer", func() bool { return w.peer(key) != nil })
	return w.peer(key)
}

// TestConnectWrongKey dials an address that holds another key: the dial fails, nothing is admitted, the pair of key
// and address backs off and the host waits RetryMin, but the key's own history is untouched and the address is not
// backed off. A key lookups vouched for at that address connects at once, and its success clears the address's and
// its pair's backoff.
func TestConnectWrongKey(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("wrong key")
	a, b, wa, wb := connectPair(t, nil, nil, topic)
	other, at := ident(t).PublicKey(), addrOf(b.Addr())
	err := a.Connect(testCtx(t, 10*time.Second), topic, other, at, loop)
	if !errors.Is(err, ErrLost) || !errors.Is(err, kolosecure.ErrUnexpectedPeer) {
		t.Fatalf("Connect to another key: %v", err)
	}
	checkNoPeerContent(t, err, other, at)
	if n, _ := a.slotCounts(); n != 0 || wa.count() != 0 || wb.count() != 0 {
		t.Fatalf("places %d, peers %d and %d after a failed dial", n, wa.count(), wb.count())
	}
	now := time.Now()
	a.mu.Lock()
	h := a.historyLocked(key(other))
	_, end := a.endFails[at]
	pr, host := backingOff(a.pairFails, pair{key(other), at}, now), now.Before(a.hostFloor[at.Addr()])
	a.mu.Unlock()
	if h != nil || end || !pr || !host {
		t.Fatalf("key history %v, address entry %v, pair backoff %v, host wait %v", h, end, pr, host)
	}
	if err := a.Connect(testCtx(t, 5*time.Second), topic, b.PublicKey(), at, loop); !errors.Is(err, ErrWait) {
		t.Fatalf("a key no lookup vouched at the waiting host: %v", err)
	}
	a.mu.Lock()
	a.past[key(b.PublicKey())] = &history{addr: at}
	a.past[key(other)] = &history{addr: at} // past the host's wait, so only the pair refuses it
	a.endFails[at] = &failure{fails: 3}
	a.pairFails[pair{key(b.PublicKey()), at}] = &failure{fails: 3}
	a.mu.Unlock()
	if err := a.Connect(testCtx(t, 5*time.Second), topic, other, at, loop); !errors.Is(err, ErrWait) {
		t.Fatalf("Connect to the pair in backoff: %v", err)
	}
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), at, loop); err != nil {
		t.Fatalf("the vouched key at the waiting host: %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, end = a.endFails[at]
	_, pr = a.pairFails[pair{key(b.PublicKey()), at}]
	if end || pr || a.pairFails[pair{key(other), at}] == nil {
		t.Fatalf("after success: address entry %v, pair entry %v, other pair kept %v", end, pr, a.pairFails[pair{key(other), at}] != nil)
	}
}

// TestConnectRemoteNotJoined checks that a target that has not joined the topic refuses the connection: in its hello
// when it arbitrates, else once the dialer admitted it, which then loses it with ErrRefused.
func TestConnectRemoteNotJoined(t *testing.T) {
	small, large := identPair(t)
	for _, tc := range []struct {
		name           string
		dialer, target *koloid.Identity
	}{{"dialer arbitrates", small, large}, {"target arbitrates", large, small}} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			topic := topicOf("joined here")
			a, b, wa, wb := connectPair(t, tc.dialer, tc.target, topic)
			b.Leave(topic)
			join(t, b, topicOf("joined there"), &JoinOptions{Lookup: true})
			err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop)
			if tc.dialer == small {
				if err != nil {
					t.Fatalf("arbiter's Connect: %v", err)
				}
				waitFor(t, 5*time.Second, "Lost", func() bool { return wa.kinds(Lost) == 1 })
				wa.mu.Lock()
				lostErr := wa.events[len(wa.events)-1].Err
				wa.mu.Unlock()
				if !errors.Is(lostErr, ErrRefused) {
					t.Fatalf("Lost with %v", lostErr)
				}
			} else if !errors.Is(err, ErrRefused) {
				t.Fatalf("Connect: %v", err)
			}
			waitFor(t, 5*time.Second, "no slot", func() bool { n, _ := a.slotCounts(); return n == 0 })
			if wa.count() != 0 || wb.count() != 0 {
				t.Fatal("refused connection left a peer")
			}
			now := time.Now()
			a.mu.Lock()
			h := a.historyLocked(key(b.PublicKey()))
			pr := backingOff(a.pairFails, pair{key(b.PublicKey()), addrOf(b.Addr())}, now)
			a.mu.Unlock()
			if h != nil || !pr {
				t.Fatalf("a key lookups never vouched for: history %+v, pair backoff %v", h, pr)
			}
		})
	}
}

func checkNoPeerContent(t *testing.T, err error, key ed25519.PublicKey, addr netip.AddrPort) {
	t.Helper()
	msg := err.Error()
	if !strings.HasPrefix(msg, "koloswarm:") {
		t.Errorf("error %q does not start with koloswarm:", msg)
	}
	for _, sec := range []string{hex.EncodeToString(key), string(key), addr.Addr().String()} {
		if strings.Contains(msg, sec) {
			t.Errorf("error %q contains peer content", msg)
		}
	}
}

// TestConnectArguments checks that bad arguments, IPv6 addresses in every form among them, our own address and
// addresses outside the scope of from are refused before any dial.
func TestConnectArguments(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	s.hooks.dial = func(context.Context, netip.AddrPort, ed25519.PublicKey) (*kolosecure.Conn, error) {
		t.Error("dial for a refused argument")
		return nil, errors.New("no dial")
	}
	topic := topicOf("arguments")
	join(t, s, topic, &JoinOptions{Lookup: true})
	ctx := testCtx(t, 5*time.Second)
	key := ident(t).PublicKey()
	ok := netip.MustParseAddrPort("127.0.0.1:4000")
	for _, tc := range []struct {
		name  string
		topic Topic
		key   ed25519.PublicKey
		addr  string
		from  string
		ipv6  bool
	}{
		{"IPv6 loopback", topic, key, "[::1]:4000", "", true},
		{"IPv4-mapped", topic, key, "[::ffff:127.0.0.1]:4000", "", true},
		{"IPv6 global", topic, key, "[2001:db8::1]:4000", "", true},
		{"IPv6 from", topic, key, ok.String(), "::1", true},
		{"IPv4-mapped from", topic, key, ok.String(), "::ffff:127.0.0.1", true},
		{"zero address", topic, key, "", "", false},
		{"port 0", topic, key, "127.0.0.1:0", "127.0.0.1", false},
		{"unspecified", topic, key, "0.0.0.0:4000", "", false},
		{"this network", topic, key, "0.1.2.3:4000", "", false},
		{"multicast", topic, key, "224.0.0.1:4000", "", false},
		{"broadcast", topic, key, "255.255.255.255:4000", "", false},
		{"reserved", topic, key, "240.0.0.1:4000", "", false},
		{"loopback from a global peer", topic, key, "127.0.0.2:4000", "198.18.0.1", false},
		{"private from a global peer", topic, key, "192.168.1.5:4000", "198.18.0.1", false},
		{"link-local from a global peer", topic, key, "169.254.1.1:4000", "198.18.0.1", false},
		{"CGNAT from a global peer", topic, key, "100.64.1.1:4000", "198.18.0.1", false},
		{"loopback from a private peer", topic, key, "127.0.0.2:4000", "192.168.1.1", false},
		{"private from a CGNAT peer", topic, key, "192.168.1.5:4000", "100.100.1.1", false},
		{"CGNAT from a private peer", topic, key, "100.64.1.1:4000", "192.168.1.1", false},
		{"private from an unknown source", topic, key, "192.168.1.5:4000", "", false},
		{"loopback from an unknown source", topic, key, "127.0.0.2:4000", "", false},
		{"own address", topic, key, addrOf(s.Addr()).String(), "127.0.0.1", false},
		{"short key", topic, key[:31], ok.String(), "127.0.0.1", false},
		{"nil key", topic, nil, ok.String(), "127.0.0.1", false},
		{"own key", topic, s.PublicKey(), ok.String(), "127.0.0.1", false},
		{"topic not joined", topicOf("other"), key, ok.String(), "127.0.0.1", false},
	} {
		var addr netip.AddrPort
		if tc.addr != "" {
			addr = netip.MustParseAddrPort(tc.addr)
		}
		var from netip.Addr
		if tc.from != "" {
			from = netip.MustParseAddr(tc.from)
		}
		err := s.Connect(ctx, tc.topic, tc.key, addr, from)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := strings.Contains(err.Error(), "IPv6"); got != tc.ipv6 {
			t.Errorf("%s: %q", tc.name, err)
		}
	}
	if n, _ := s.slotCounts(); n != 0 {
		t.Fatalf("%d slots after refused arguments", n)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Connect(canceled, topic, key, ok, loop); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ctx: %v", err)
	}
	s.Close()
	if err := s.Connect(ctx, topic, key, ok, loop); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
}

// TestIsOwn checks the own-address rule, also for a node that listens on every address.
func TestIsOwn(t *testing.T) {
	ap := netip.MustParseAddrPort
	ifaces := func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(192, 168, 1, 2), Mask: net.CIDRMask(24, 32)}, &net.IPAddr{IP: net.IPv4(10, 0, 0, 9)}}, nil
	}
	broken := func() ([]net.Addr, error) { return nil, errors.New("no interfaces") }
	for _, tc := range []struct {
		local, addr string
		want        bool
	}{
		{"127.0.0.1:4000", "127.0.0.1:4000", true},
		{"127.0.0.1:4000", "127.0.0.1:4001", false},
		{"127.0.0.1:4000", "127.0.0.2:4000", false},
		{"0.0.0.0:4000", "127.0.0.1:4000", true},
		{"0.0.0.0:4000", "127.0.0.5:4000", true},
		{"0.0.0.0:4000", "192.168.1.2:4000", true},
		{"0.0.0.0:4000", "192.168.1.3:4000", false},
		{"0.0.0.0:4000", "10.0.0.9:4000", false},
		{"0.0.0.0:4000", "127.0.0.1:4001", false},
		{"0.0.0.0:4000", "192.168.1.2:4001", false},
		{"192.168.1.2:4000", "127.0.0.1:4000", false},
		{"192.168.1.2:4000", "192.168.1.2:4000", true},
		{"10.0.0.5:4000", "192.168.1.2:4000", false},
	} {
		if got := isOwn(ap(tc.local), ap(tc.addr), ifaces); got != tc.want {
			t.Errorf("isOwn(%s, %s) = %v", tc.local, tc.addr, got)
		}
	}
	if isOwn(ap("0.0.0.0:4000"), ap("192.168.1.2:4000"), broken) {
		t.Error("isOwn with no interface list matched an interface address")
	}
}

// TestConnectScope checks the addresses Connect dials for each source: global or in the scope of from, and global
// only when from is zero.
func TestConnectScope(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxConnecting = 16
	s := newSwarm(t, nil, nil, cfg)
	bl := blockDials(s)
	topic := topicOf("scope")
	join(t, s, topic, &JoinOptions{Lookup: true})
	for _, tc := range []struct{ addr, from string }{
		{"192.168.1.5:9", "192.168.1.1"},
		{"10.0.0.1:9", "10.1.1.1"},
		{"198.18.0.7:9", "192.168.1.1"},
		{"127.0.0.3:9", "127.0.0.1"},
		{"198.18.0.8:9", ""},
	} {
		var from netip.Addr
		if tc.from != "" {
			from = netip.MustParseAddr(tc.from)
		}
		ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
		errc := bl.connectAsyncFrom(t, ctx, s, topic, netip.MustParseAddrPort(tc.addr), from)
		cancel()
		if err := waitErr(t, errc); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s from %q: %v", tc.addr, tc.from, err)
		}
	}
}

// blocker replaces Connect's dial with one that waits for its context, and reports each dial it starts.
type blocker struct {
	started chan netip.AddrPort
}

func blockDials(s *Swarm) *blocker {
	b := &blocker{started: make(chan netip.AddrPort, 16)}
	s.hooks.dial = func(ctx context.Context, addr netip.AddrPort, _ ed25519.PublicKey) (*kolosecure.Conn, error) {
		b.started <- addr
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return b
}

// connectAsync starts Connect of a new key at addr, learned by us, and returns its result channel once its dial has
// started.
func (b *blocker) connectAsync(t *testing.T, ctx context.Context, s *Swarm, topic Topic, addr netip.AddrPort) <-chan error {
	t.Helper()
	return b.connectAsyncFrom(t, ctx, s, topic, addr, netip.Addr{})
}

// connectAsyncFrom is connectAsync for an address the peer at from supplied.
func (b *blocker) connectAsyncFrom(t *testing.T, ctx context.Context, s *Swarm, topic Topic, addr netip.AddrPort, from netip.Addr) <-chan error {
	t.Helper()
	errc := make(chan error, 1)
	pub := ident(t).PublicKey()
	go func() { errc <- s.Connect(ctx, topic, pub, addr, from) }()
	select {
	case <-b.started:
	case err := <-errc:
		t.Fatalf("Connect returned before dialing: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("dial not started")
	}
	return errc
}

func waitErr(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not return")
		return nil
	}
}

// TestConnectBounds checks that Connect keeps MaxConnecting, one dial per host, MaxPeers and the topic's MaxPeers, and
// that Allow refuses before any dial.
func TestConnectBounds(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxConnecting = 2
	cfg.MaxPeers = 4
	cfg.MaxInbound = 1
	cfg.MaxConnectPeers = 3
	refused := fakeAddr()
	cfg.Allow = func(_ ed25519.PublicKey, addr netip.AddrPort) bool { return addr != refused }
	s := newSwarm(t, nil, nil, cfg)
	bl := blockDials(s)
	t1, t2 := topicOf("bounds 1"), topicOf("bounds 2")
	join(t, s, t1, &JoinOptions{Lookup: true, MaxPeers: 1})
	join(t, s, t2, &JoinOptions{Lookup: true})
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer cancel()

	if err := s.Connect(ctx, t2, ident(t).PublicKey(), refused, netip.Addr{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("Allow: %v", err)
	}
	host := fakeAddr()
	first := bl.connectAsync(t, ctx, s, t1, host)
	if err := s.Connect(ctx, t1, ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("topic MaxPeers: %v", err)
	}
	if err := s.Connect(ctx, t2, ident(t).PublicKey(), netip.AddrPortFrom(host.Addr(), host.Port()+1), netip.Addr{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("second dial to one host: %v", err)
	}
	second := bl.connectAsync(t, ctx, s, t2, fakeAddr())
	// A full dial-start bucket, so only MaxConnecting can refuse the third dial.
	s.mu.Lock()
	s.connectFill = s.connectFill.Add(-time.Hour)
	s.mu.Unlock()
	if err := s.Connect(ctx, t2, ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, ErrWait) {
		t.Fatalf("MaxConnecting: %v", err)
	}
	if n, _ := s.slotCounts(); n != 2 {
		t.Fatalf("%d slots, want 2", n)
	}
	cancel()
	for _, errc := range []<-chan error{first, second} {
		if err := waitErr(t, errc); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Connect: %v", err)
		}
	}
	if n, _ := s.slotCounts(); n != 0 {
		t.Fatalf("%d slots after cancel", n)
	}
	s.mu.Lock()
	connects := s.dialsRunningLocked()
	s.mu.Unlock()
	if connects != 0 {
		t.Fatalf("%d Connect dials counted after cancel", connects)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.past) != 0 || len(s.endFails) != 0 || len(s.pairFails) != 0 || len(s.hostFloor) != 0 {
		t.Fatal("a canceled Connect grew a backoff")
	}
}

// TestConnectMaxPeers checks that Connect counts the places of every kind in MaxPeers.
func TestConnectMaxPeers(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxPeers = 2
	cfg.MaxInbound = 1
	cfg.MaxConnectPeers = 1
	s := newSwarm(t, nil, nil, cfg)
	blockDials(s)
	topic, other := topicOf("max peers"), topicOf("max peers other")
	join(t, s, topic, &JoinOptions{Lookup: true})
	join(t, s, other, &JoinOptions{Lookup: true})
	// The places are on another topic, so only MaxPeers can refuse.
	for _, inbound := range []bool{true, false} {
		k := ident(t).PublicKey()
		if _, _, err := s.admit(newFake(k), key(k), fakeAddr(), inbound, true, []Topic{other}, false, generation{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Connect(testCtx(t, 5*time.Second), topic, ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, errFull) || errors.Is(err, ErrWait) {
		t.Fatalf("MaxPeers: %v", err)
	}
}

// TestConnectMaxConnectPeers checks that Connect places, dialing or connected, stop at MaxConnectPeers, and that a
// Connect dial does not take kolo-dht's MaxConnecting budget.
func TestConnectMaxConnectPeers(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxConnectPeers = 1
	s := newSwarm(t, nil, nil, cfg)
	bl := blockDials(s)
	t1, t2 := topicOf("connect peers 1"), topicOf("connect peers 2")
	join(t, s, t1, &JoinOptions{Lookup: true})
	join(t, s, t2, &JoinOptions{Lookup: true})
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer cancel()
	first := bl.connectAsync(t, ctx, s, t1, fakeAddr())
	if err := s.Connect(ctx, t2, ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, errFull) {
		t.Fatalf("MaxConnectPeers while dialing: %v", err)
	}
	s.mu.Lock()
	dialing := s.dialing
	s.mu.Unlock()
	if dialing != 0 {
		t.Fatalf("a Connect dial counted as a kolo-dht dial: %d", dialing)
	}
	cancel()
	if err := waitErr(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Connect: %v", err)
	}

	topic := topicOf("connect peers")
	a, b := newSwarm(t, nil, nil, cfg), newSwarm(t, nil, nil, nil)
	c := newSwarm(t, nil, nil, nil)
	for _, x := range []*Swarm{a, b, c} {
		join(t, x, topic, &JoinOptions{Lookup: true})
	}
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := a.Connect(testCtx(t, 10*time.Second), topic, c.PublicKey(), addrOf(c.Addr()), loop); !errors.Is(err, errFull) {
		t.Fatalf("MaxConnectPeers while connected: %v", err)
	}
}

// TestConnectRate checks that Connect starts at most MaxConnecting dials per RetryMin, refilled in proportion.
func TestConnectRate(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxConnecting = 2
	cfg.RetryMin, cfg.RetryMax = time.Minute, time.Minute
	s := newSwarm(t, nil, nil, cfg)
	s.hooks.dial = func(context.Context, netip.AddrPort, ed25519.PublicKey) (*kolosecure.Conn, error) {
		return nil, errors.New("no answer")
	}
	topic := topicOf("rate")
	join(t, s, topic, &JoinOptions{Lookup: true})
	ctx := testCtx(t, 10*time.Second)
	try := func(want error) {
		t.Helper()
		if err := s.Connect(ctx, topic, ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, want) {
			t.Fatalf("Connect: %v, want %v", err, want)
		}
	}
	back := func(d time.Duration) {
		s.mu.Lock()
		s.connectFill = s.connectFill.Add(-d)
		s.mu.Unlock()
	}
	try(ErrLost)
	try(ErrLost)
	try(ErrWait)
	back(30 * time.Second)
	try(ErrLost)
	try(ErrWait)
	back(10 * time.Minute)
	try(ErrLost)
	try(ErrLost)
	try(ErrWait)
}

// TestConnectLeaveAndClose checks that Leave ends a Connect dial for the topic with ErrRefused and Close with ErrClosed.
func TestConnectLeaveAndClose(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	bl := blockDials(s)
	t1, t2 := topicOf("leave"), topicOf("stay")
	join(t, s, t1, &JoinOptions{Lookup: true})
	join(t, s, t2, &JoinOptions{Lookup: true})
	ctx := testCtx(t, 10*time.Second)
	left := bl.connectAsync(t, ctx, s, t1, fakeAddr())
	stays := bl.connectAsync(t, ctx, s, t2, fakeAddr())
	s.Leave(t1)
	if err := waitErr(t, left); !errors.Is(err, errTopicLeft) {
		t.Fatalf("Leave: %v", err)
	}
	if n, _ := s.slotCounts(); n != 1 {
		t.Fatalf("%d slots after Leave, want 1", n)
	}
	s.Close()
	if err := waitErr(t, stays); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
}

// TestConnectLossBacksOff checks that a lost connection delays the next Connect of the dialer, while the side that
// accepted it keeps no backoff.
func TestConnectLossBacksOff(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("lost")
	cfg := fastConfig()
	cfg.RetryMin, cfg.RetryMax = time.Minute, time.Minute
	a, b := newSwarm(t, nil, nil, cfg), newSwarm(t, nil, nil, nil)
	wa, wb := watch(t, a), watch(t, b)
	join(t, a, topic, &JoinOptions{Lookup: true})
	join(t, b, topic, &JoinOptions{Lookup: true})
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	wa.wait(t, b.PublicKey())
	wb.wait(t, a.PublicKey()).Conn().CloseWithError(codeNormal, "")
	waitFor(t, 5*time.Second, "lost", func() bool { return wa.count() == 0 && wb.count() == 0 })
	if err := a.Connect(testCtx(t, 5*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); !errors.Is(err, ErrRefused) {
		t.Fatalf("Connect right after a loss: %v", err)
	}
	if err := b.Connect(testCtx(t, 10*time.Second), topic, a.PublicKey(), addrOf(a.Addr()), loop); err != nil {
		t.Fatalf("Connect from the accepting side: %v", err)
	}
	wa.wait(t, b.PublicKey())
}

// TestConnectInternalBounds covers the bounds that need swarm state no loopback setup holds still: a topic still being
// joined, a hello of the key in progress, a host whose only dial already settled (it holds no kolo-dht session), and a
// topic whose inbound share is full, which does not limit an outbound Connect.
func TestConnectInternalBounds(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	bl := blockDials(s)
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer cancel()
	joining := topicOf("joining")
	s.mu.Lock()
	s.topics[joining] = &topicState{opts: JoinOptions{Lookup: true, MaxPeers: 2}, ctx: ctx, cancel: func() {}, joining: true}
	s.mu.Unlock()
	if err := s.Connect(ctx, joining, ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("topic being joined: %v", err)
	}
	s.mu.Lock()
	delete(s.topics, joining)
	s.mu.Unlock()

	topic := topicOf("inbound share")
	join(t, s, topic, &JoinOptions{Lookup: true, MaxPeers: 2})
	busy := ident(t).PublicKey()
	s.mu.Lock()
	s.helloKey[key(busy)] = 1
	s.mu.Unlock()
	if err := s.Connect(ctx, topic, busy, fakeAddr(), netip.Addr{}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("hello in progress: %v", err)
	}
	s.mu.Lock()
	delete(s.helloKey, key(busy))
	s.mu.Unlock()

	settled := fakeAddr()
	other := key(ident(t).PublicKey())
	s.mu.Lock()
	s.slots[other] = &slot{topic: topic, own: settled.Addr(), settled: true}
	s.mu.Unlock()
	errc := bl.connectAsync(t, ctx, s, topic, settled)
	s.mu.Lock()
	for _, d := range s.dials {
		d.cancel()
	}
	delete(s.slots, other)
	s.mu.Unlock()
	if err := waitErr(t, errc); err == nil {
		t.Fatal("canceled Connect returned nil")
	}

	in := ident(t).PublicKey()
	if _, _, err := s.admit(newFake(in), key(in), fakeAddr(), true, true, []Topic{topic}, false, generation{}); err != nil {
		t.Fatal(err)
	}
	errc = bl.connectAsync(t, ctx, s, topic, fakeAddr())
	cancel()
	if err := waitErr(t, errc); !errors.Is(err, context.Canceled) {
		t.Fatalf("outbound Connect with the inbound share full: %v", err)
	}
}

// TestConnectSmallOrderKey checks that a key kolo-secure refuses is ErrInvalidArgument and grows no backoff.
func TestConnectSmallOrderKey(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("small order")
	a, b, _, _ := connectPair(t, nil, nil, topic)
	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1
	if err := a.Connect(testCtx(t, 5*time.Second), topic, identity, addrOf(b.Addr()), loop); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("small-order key: %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.past) != 0 || len(a.slots) != 0 || len(a.dials) != 0 || len(a.endFails) != 0 || len(a.pairFails) != 0 || len(a.hostFloor) != 0 {
		t.Fatal("a refused key left a backoff or a slot")
	}
}

// TestConnectSameHost checks that a connected peer does not hold its host: only a dial in progress does.
func TestConnectSameHost(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("same host")
	a, b, wa, _ := connectPair(t, nil, nil, topic)
	c := newSwarm(t, nil, nil, nil)
	join(t, c, topic, &JoinOptions{Lookup: true})
	for _, x := range []*Swarm{b, c} {
		if err := a.Connect(testCtx(t, 10*time.Second), topic, x.PublicKey(), addrOf(x.Addr()), loop); err != nil {
			t.Fatalf("Connect: %v", err)
		}
		wa.wait(t, x.PublicKey())
	}
}

// TestConnectAdmittedMeanwhile checks that a Connect whose key reached us while it dialed, by the key's own Connect or
// by Attach, returns nil and drops its own connection without replacing the admitted one, whose place keeps its
// direction.
func TestConnectAdmittedMeanwhile(t *testing.T) {
	for _, tc := range []struct {
		name           string
		attach, relays bool
	}{{"connect", false, false}, {"attach", true, false}, {"connect with relays", false, true}} {
		attach := tc.attach
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			topic := topicOf("meanwhile")
			ia, ib := ident(t), ident(t)
			cfg := fastConfig()
			if tc.relays {
				// With relays, only a relayed peer would give its place to the direct dial.
				cfg.Relays = []Relay{{Addr: "127.0.0.1:9", PublicKey: ident(t).PublicKey()}}
			}
			a, b := newSwarm(t, nil, ia, cfg), newSwarm(t, nil, ib, nil)
			wa, wb := watch(t, a), watch(t, b)
			join(t, a, topic, &JoinOptions{Lookup: true})
			join(t, b, topic, &JoinOptions{Lookup: true})
			started := make(chan struct{})
			a.hooks.dial = func(ctx context.Context, addr netip.AddrPort, pub ed25519.PublicKey) (*kolosecure.Conn, error) {
				close(started)
				until(5*time.Second, func() bool { return wa.peer(pub) != nil })
				return kolosecure.Dial(ctx, addr.String(), a.id, pub, a.cfg.DHT.Secure)
			}
			errc := make(chan error, 1)
			cctx := testCtx(t, 10*time.Second)
			go func() {
				errc <- a.Connect(cctx, topic, b.PublicKey(), addrOf(b.Addr()), loop)
			}()
			<-started
			if attach {
				ca, cb := securePair(t, ia, ib)
				if ea, eb := attachBoth(t, a, b, ca, cb); ea != nil || eb != nil {
					t.Fatalf("Attach: %v, %v", ea, eb)
				}
			} else if err := b.Connect(testCtx(t, 10*time.Second), topic, a.PublicKey(), addrOf(a.Addr()), loop); err != nil {
				t.Fatalf("Connect from the target: %v", err)
			}
			if err := waitErr(t, errc); !errors.Is(err, ErrDuplicate) {
				t.Fatalf("Connect admitted meanwhile: %v", err)
			}
			pa := wa.wait(t, b.PublicKey())
			if pa.Outbound() != attach {
				t.Fatalf("outbound %v: b's own Connect gives a an inbound place, a's Attach an outbound one", pa.Outbound())
			}
			// Once no hello of the key runs on either side, the dropped connection can no longer change anything.
			waitFor(t, 5*time.Second, "no hello in progress", func() bool { return idle(a, ib.PublicKey()) && idle(b, ia.PublicKey()) })
			if wa.kinds(Connected) != 1 || wb.kinds(Connected) != 1 || wa.kinds(Lost) != 0 || wb.kinds(Lost) != 0 {
				t.Fatalf("Connected %d and %d, Lost %d and %d", wa.kinds(Connected), wb.kinds(Connected), wa.kinds(Lost), wb.kinds(Lost))
			}
			if wa.peer(b.PublicKey()) != pa {
				t.Fatal("admitted peer replaced")
			}
		})
	}
}

// TestConnectSilentPeer checks a hello that starts with ctx already done: it ends with ctx's error, and the caller's
// deadline backs off the pair and makes the host wait, except at an address lookups found for the key, while a cancel
// counts for nothing; the address itself and the key's history are never charged.
func TestConnectSilentPeer(t *testing.T) {
	for _, tc := range []struct {
		name               string
		deadline, vouched  bool
		wantPair, wantHost bool
	}{
		{"deadline", true, false, true, true},
		{"deadline at a vouched address", true, true, false, false},
		{"cancel", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			topic := topicOf("silent")
			s := newSwarm(t, nil, nil, nil)
			join(t, s, topic, &JoinOptions{Lookup: true})
			silent := ident(t)
			l, err := kolosecure.Listen(testCtx(t, 10*time.Second), "127.0.0.1:0", silent, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { l.Close() })
			at, k := addrOf(l.Addr()), key(silent.PublicKey())
			if tc.vouched {
				s.mu.Lock()
				s.past[k] = &history{addr: at}
				s.mu.Unlock()
			}
			ctx, cancel := context.WithCancel(context.Background())
			if tc.deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
			}
			defer cancel()
			dialCtx := testCtx(t, 10*time.Second)
			s.hooks.dial = func(_ context.Context, addr netip.AddrPort, pub ed25519.PublicKey) (*kolosecure.Conn, error) {
				c, err := kolosecure.Dial(dialCtx, addr.String(), s.id, pub, s.cfg.DHT.Secure)
				if !tc.deadline {
					cancel()
				}
				<-ctx.Done()
				return c, err
			}
			if err := s.Connect(ctx, topic, silent.PublicKey(), at, loop); !errors.Is(err, ctx.Err()) {
				t.Fatalf("silent peer: %v", err)
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			_, end := s.endFails[at]
			_, pr := s.pairFails[pair{k, at}]
			_, host := s.hostFloor[at.Addr()]
			h := s.past[k]
			if len(s.slots) != 0 || end || pr != tc.wantPair || host != tc.wantHost || h != nil && h.fails != 0 {
				t.Fatalf("slots %d, address backoff %v, pair backoff %v, host wait %v, history %+v", len(s.slots), end, pr, host, h)
			}
		})
	}
}

// TestFoundTopicsConnectFirst checks that the hello claims a Connect dial's topic first and once.
func TestFoundTopicsConnectFirst(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	t1, t2 := topicOf("found 1"), topicOf("found 2")
	join(t, s, t1, &JoinOptions{Lookup: true})
	join(t, s, t2, &JoinOptions{Lookup: true})
	k := key(ident(t).PublicKey())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cands[k] = &cand{topics: map[Topic]bool{t1: true, t2: true}}
	s.slots[k] = &slot{topic: t2, connect: true}
	got := s.foundTopicsLocked(k)
	if len(got) != 2 || got[0] != t2 || got[1] != t1 {
		t.Fatalf("topics %x", got)
	}
	s.cands[k] = &cand{topics: map[Topic]bool{t1: true}}
	s.slots[k] = &slot{topic: t2}
	if got := s.foundTopicsLocked(k); len(got) != 1 || got[0] != t1 {
		t.Fatalf("a lookup dial's slot topic claimed: %x", got)
	}
	s.slots[k] = &slot{topic: topicOf("not joined"), connect: true}
	if got := s.foundTopicsLocked(k); len(got) != 1 || got[0] != t1 {
		t.Fatalf("a topic not joined claimed: %x", got)
	}
	delete(s.slots, k)
	delete(s.cands, k)
}

// TestConnectReplacesRelayed checks that, with Config.Relays, a relayed connection admitted while Connect dialed is
// replaced by Connect's direct one, as a dial from a lookup does.
func TestConnectReplacesRelayed(t *testing.T) {
	small, large := identPair(t)
	for _, tc := range []struct {
		name   string
		ia, ib *koloid.Identity
	}{{"dialer arbitrates", small, large}, {"target arbitrates", large, small}} {
		t.Run(tc.name, func(t *testing.T) { replacesRelayed(t, tc.ia, tc.ib) })
	}
}

func replacesRelayed(t *testing.T, ia, ib *koloid.Identity) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.Relays = []Relay{{Addr: "127.0.0.1:9", PublicKey: ident(t).PublicKey()}}
	topic := topicOf("replace relayed")
	a, b := newSwarm(t, nil, ia, cfg), newSwarm(t, nil, ib, nil)
	wa, wb := watch(t, a), watch(t, b)
	join(t, a, topic, &JoinOptions{Lookup: true})
	join(t, b, topic, &JoinOptions{Lookup: true})
	started, release := make(chan struct{}), make(chan struct{})
	a.hooks.dial = func(ctx context.Context, addr netip.AddrPort, pub ed25519.PublicKey) (*kolosecure.Conn, error) {
		close(started)
		<-release
		return kolosecure.Dial(ctx, addr.String(), a.id, pub, a.cfg.DHT.Secure)
	}
	errc := make(chan error, 1)
	cctx := testCtx(t, 10*time.Second)
	go func() {
		errc <- a.Connect(cctx, topic, ib.PublicKey(), addrOf(b.Addr()), loop)
	}()
	<-started
	ca, cb := securePair(t, ia, ib)
	if ea, eb := attachBoth(t, a, b, relayed{ca}, cb); ea != nil || eb != nil {
		t.Fatalf("Attach: %v, %v", ea, eb)
	}
	if p := wa.wait(t, ib.PublicKey()); p.Direct() {
		t.Fatal("attached peer reported direct")
	}
	if bytes.Compare(ib.PublicKey(), ia.PublicKey()) < 0 {
		// The far side arbitrates and closes the relayed connection before its reply: a sees that loss before it
		// admits, so the place must stay the Connect's meanwhile.
		a.mu.Lock()
		a.hooks.afterHello = func() {
			until(5*time.Second, func() bool { return wa.kinds(Lost) == 1 })
		}
		a.mu.Unlock()
	}
	close(release)
	if err := waitErr(t, errc); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	waitFor(t, 5*time.Second, "direct peer on both sides", func() bool {
		pa, pb := wa.peer(ib.PublicKey()), wb.peer(ia.PublicKey())
		return pa != nil && pa.Direct() && pb != nil && pb.Direct()
	})
	if wa.kinds(Lost) != 1 {
		t.Fatalf("%d Lost events, want 1 for the replaced relayed peer", wa.kinds(Lost))
	}
}

// TestConnectHelloKeyFull checks that a dial that connects while the key already has its two hellos running drops its
// connection with ErrDuplicate.
func TestConnectHelloKeyFull(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("hellos full")
	a, b, wa, _ := connectPair(t, nil, nil, topic)
	k := key(b.PublicKey())
	a.hooks.dial = func(ctx context.Context, addr netip.AddrPort, pub ed25519.PublicKey) (*kolosecure.Conn, error) {
		a.mu.Lock()
		a.helloKey[k] = helloPerKey
		a.mu.Unlock()
		return kolosecure.Dial(ctx, addr.String(), a.id, pub, a.cfg.DHT.Secure)
	}
	err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop)
	a.mu.Lock()
	delete(a.helloKey, k)
	a.mu.Unlock()
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("Connect with the key's hellos full: %v", err)
	}
	if n, _ := a.slotCounts(); n != 0 || wa.count() != 0 {
		t.Fatal("dropped connection left a slot or a peer")
	}
}

// TestConnectUsesSecureConfig checks that Connect's connection has the swarm's kolo-secure and kolo-transport settings:
// with MaxIncomingStreams 1, the peer cannot open a second stream while the first is open.
func TestConnectUsesSecureConfig(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("secure config")
	cfg := fastConfig()
	cfg.DHT.Secure.Transport.MaxIncomingStreams = 1
	a := newSwarm(t, nil, nil, cfg)
	b := newSwarm(t, nil, nil, nil)
	wb := watch(t, b)
	join(t, a, topic, &JoinOptions{Lookup: true})
	join(t, b, topic, &JoinOptions{Lookup: true})
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	c := wb.wait(t, a.PublicKey()).Conn()
	st, err := c.OpenStream(testCtx(t, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if st2, err := c.OpenStream(short); err == nil {
		st2.Close()
		t.Fatal("a second stream opened past MaxIncomingStreams 1")
	}
}

// loop is the source of the loopback addresses the tests dial: Connect dials loopback only for a loopback source.
var loop = netip.MustParseAddr("127.0.0.1")

// elsewhere is a topic no swarm joins, so a candidate on it is never dialed by lookups during a test.
var elsewhere = topicOf("elsewhere")

func setCand(s *Swarm, pub ed25519.PublicKey, at netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cands[key(pub)] = &cand{rec: kolodht.Record{Topic: elsewhere, PublicKey: pub, Addr: at}, topics: map[Topic]bool{elsewhere: true}}
}

// TestConnectFalseAddressSparesKey checks that a dial to a false address for an honest key, which fails before the key
// proved itself, backs off the pair, and the host only when nothing answered, but never the key's own history.
func TestConnectFalseAddressSparesKey(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	topic := topicOf("false address")
	join(t, s, topic, &JoinOptions{Lookup: true})
	honest := ident(t).PublicKey()
	k := key(honest)
	setCand(s, honest, fakeAddr())
	ctx := testCtx(t, 10*time.Second)
	for _, fail := range []error{errors.New("no answer"), kolosecure.ErrUnexpectedPeer} {
		silent := !errors.Is(fail, kolosecure.ErrUnexpectedPeer)
		s.hooks.dial = func(context.Context, netip.AddrPort, ed25519.PublicKey) (*kolosecure.Conn, error) { return nil, fail }
		bogus := fakeAddr()
		if err := s.Connect(ctx, topic, honest, bogus, netip.Addr{}); !errors.Is(err, ErrLost) {
			t.Fatalf("Connect to a false address: %v", err)
		}
		now := time.Now()
		s.mu.Lock()
		h, inPast := s.cands[k].history, s.past[k] != nil
		end := backingOff(s.endFails, bogus, now)
		host := now.Before(s.hostFloor[bogus.Addr()])
		fails := 0
		if f := s.pairFails[pair{k, bogus}]; f != nil && now.Before(f.next) {
			fails = f.fails
		}
		s.mu.Unlock()
		if h != (history{}) || inPast || end != silent || !host || fails != 1 {
			t.Fatalf("key history %+v, in past %v, address backoff %v, host wait %v, pair fails %d", h, inPast, end, host, fails)
		}
		// The host waits RetryMin for any key lookups did not vouch there.
		other := netip.AddrPortFrom(bogus.Addr(), bogus.Port()+1)
		if err := s.Connect(ctx, topic, ident(t).PublicKey(), other, netip.Addr{}); !errors.Is(err, ErrWait) {
			t.Fatalf("another key at a host that just failed: %v", err)
		}
	}
	// The key's own backoff, from lookups, still holds it at any address.
	s.mu.Lock()
	s.cands[k].next = time.Now().Add(time.Hour)
	s.connectFill = s.connectFill.Add(-time.Hour) // a full dial-start bucket, so only the key's backoff can refuse
	s.mu.Unlock()
	if err := s.Connect(ctx, topic, honest, fakeAddr(), netip.Addr{}); !errors.Is(err, ErrWait) {
		t.Fatalf("a key in its own backoff: %v", err)
	}
}

// TestConnectProvedFailure checks where a failure after the key proved itself goes, by the hello or by the lost
// connection: to the candidate's backoff when its record has the dialed address, else to the pair's.
func TestConnectProvedFailure(t *testing.T) {
	small, large := identPair(t)
	for _, tc := range []struct {
		name           string
		dialer, target *koloid.Identity
		same           bool
	}{
		{"hello, record here", large, small, true}, {"hello, record elsewhere", large, small, false},
		{"lost, record here", small, large, true}, {"lost, record elsewhere", small, large, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			topic := topicOf("proved")
			a, b, wa, _ := connectPair(t, tc.dialer, tc.target, topic)
			b.Leave(topic)
			join(t, b, topicOf("not shared"), &JoinOptions{Lookup: true})
			at := addrOf(b.Addr())
			rec := fakeAddr()
			if tc.same {
				rec = at
			}
			setCand(a, b.PublicKey(), rec)
			err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), at, loop)
			if tc.dialer == small {
				if err != nil {
					t.Fatalf("arbiter's Connect: %v", err)
				}
				waitFor(t, 5*time.Second, "Lost", func() bool { return wa.kinds(Lost) == 1 })
			} else if !errors.Is(err, ErrRefused) {
				t.Fatalf("Connect: %v", err)
			}
			waitFor(t, 5*time.Second, "no slot", func() bool { n, _ := a.slotCounts(); return n == 0 })
			now := time.Now()
			a.mu.Lock()
			defer a.mu.Unlock()
			h := a.cands[key(b.PublicKey())].history
			pr := backingOff(a.pairFails, pair{key(b.PublicKey()), at}, now)
			_, host := a.hostFloor[at.Addr()]
			if tc.same != (h.fails == 1) || tc.same == pr || tc.same == host || h.connected {
				t.Fatalf("candidate %+v, pair backoff %v, host entry %v", h, pr, host)
			}
		})
	}
}

// TestConnectStanding checks that a Connect place earns none of the standing of a place lookups chose: no rank 0 in
// the known share, no known hello class, and no lasting outbound connection when it is lost.
func TestConnectStanding(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("standing")
	a, b, wa, wb := connectPair(t, nil, nil, topic)
	k := key(ident(t).PublicKey())
	a.mu.Lock()
	for _, x := range []struct {
		sl   *slot
		want int
	}{{&slot{connect: true, peer: &Peer{}}, -1}, {&slot{peer: &Peer{}}, 0}} {
		a.slots[k] = x.sl
		if got := a.standingLocked(k); got != x.want {
			t.Errorf("standing of %+v = %d, want %d", x.sl, got, x.want)
		}
	}
	a.mu.Unlock()
	for _, x := range []struct {
		sl   *slot
		want int
	}{{&slot{connect: true}, helloStranger}, {&slot{}, helloKnown}} {
		a.mu.Lock()
		a.slots[k] = x.sl
		a.mu.Unlock()
		tk, _, ok := a.reserveHello(k, "test", true, false)
		if !ok || tk.class != x.want {
			t.Errorf("hello class with %+v = %d (%v), want %d", x.sl, tk.class, ok, x.want)
		}
		if ok {
			a.releaseHello(tk)
		}
	}
	a.mu.Lock()
	delete(a.slots, k)
	a.mu.Unlock()

	// Lookups vouched for b's address, so the loss charges b's own history.
	a.mu.Lock()
	a.past[key(b.PublicKey())] = &history{addr: addrOf(b.Addr())}
	a.mu.Unlock()
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	pa := wa.wait(t, b.PublicKey())
	a.mu.Lock()
	pa.admitted = time.Now().Add(-time.Minute)
	a.mu.Unlock()
	wb.wait(t, a.PublicKey()).Conn().CloseWithError(codeNormal, "")
	waitFor(t, 5*time.Second, "lost", func() bool { return wa.count() == 0 })
	a.mu.Lock()
	defer a.mu.Unlock()
	if h := a.past[key(b.PublicKey())]; h == nil || h.connected || h.fails != 1 {
		t.Fatalf("history of a lost lasting Connect peer: %+v", h)
	}
}

// TestConnectNoWindowGrowth checks that the swarm never marks a connection Connect dialed for window growth, as it has
// its own kolo-transport budget, while it marks the connections it accepts.
func TestConnectNoWindowGrowth(t *testing.T) {
	small, large := identPair(t)
	for _, tc := range []struct {
		name string
		a, b *koloid.Identity
	}{{"dialer arbitrates", small, large}, {"target arbitrates", large, small}} {
		t.Run(tc.name, func(t *testing.T) { connectNoGrowth(t, tc.a, tc.b) })
	}
}

func connectNoGrowth(t *testing.T, ia, ib *koloid.Identity) {
	checkGoroutines(t)
	topic := topicOf("growth")
	cfg := fastConfig()
	cfg.Allow = func(ed25519.PublicKey, netip.AddrPort) bool { return true }
	a := newSwarm(t, nil, ia, cfg)
	b, c := newSwarm(t, nil, ib, nil), newSwarm(t, nil, nil, nil)
	wa := watch(t, a)
	var mu sync.Mutex
	var marked []ed25519.PublicKey
	a.mu.Lock()
	a.hooks.grow = func(x Conn) {
		mu.Lock()
		marked = append(marked, x.RemotePublicKey())
		mu.Unlock()
	}
	a.mu.Unlock()
	for _, x := range []*Swarm{a, b, c} {
		join(t, x, topic, &JoinOptions{Lookup: true})
	}
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := c.Connect(testCtx(t, 10*time.Second), topic, a.PublicKey(), addrOf(a.Addr()), loop); err != nil {
		t.Fatalf("Connect to a: %v", err)
	}
	waitFor(t, 5*time.Second, "both peers", func() bool { return wa.count() == 2 })
	mu.Lock()
	defer mu.Unlock()
	if len(marked) != 1 || !bytes.Equal(marked[0], c.PublicKey()) {
		t.Fatalf("marked %d connections, want only the accepted one", len(marked))
	}
}

// TestConnectAllowDuringHello checks the hello's own Allow call: when it cancels ctx, closes the swarm or admits
// another connection of the key before refusing, Connect returns ctx's error, ErrClosed or nil, and grows no backoff.
func TestConnectAllowDuringHello(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want error
	}{{"cancel", context.Canceled}, {"close", ErrClosed}, {"admit", ErrDuplicate}} {
		mode, want := tc.mode, tc.want
		t.Run(mode, func(t *testing.T) {
			checkGoroutines(t)
			topic := topicOf("allow during hello")
			ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
			defer cancel()
			ib := ident(t)
			var a *Swarm
			var calls atomic.Int32
			cfg := fastConfig()
			cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool {
				if !bytes.Equal(k, ib.PublicKey()) || calls.Add(1) != 2 {
					return true
				}
				switch mode {
				case "cancel":
					cancel()
				case "close":
					a.Close()
				case "admit":
					if _, _, err := a.admit(newFake(k), key(k), fakeAddr(), false, true, []Topic{topic}, false, generation{}); err != nil {
						t.Error(err)
					}
				}
				return false
			}
			a = newSwarm(t, nil, nil, cfg)
			b := newSwarm(t, nil, ib, nil)
			join(t, a, topic, &JoinOptions{Lookup: true})
			join(t, b, topic, &JoinOptions{Lookup: true})
			if err := a.Connect(ctx, topic, b.PublicKey(), addrOf(b.Addr()), loop); !errors.Is(err, want) {
				t.Fatalf("Connect: %v, want %v", err, want)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if len(a.past) != 0 || len(a.endFails) != 0 || len(a.pairFails) != 0 || len(a.hostFloor) != 0 {
				t.Fatal("the hello's refusal grew a backoff")
			}
		})
	}
}

// TestConnectPanicFreesSlot checks that a panic in the dial or in the hello frees the slot, the hello count and the
// dial count.
func TestConnectPanicFreesSlot(t *testing.T) {
	for _, during := range []string{"dial", "hello"} {
		t.Run(during, func(t *testing.T) {
			checkGoroutines(t)
			topic := topicOf("panic")
			a, b, _, _ := connectPair(t, nil, nil, topic)
			var dialed *kolosecure.Conn
			a.mu.Lock()
			if during == "dial" {
				a.hooks.dial = func(context.Context, netip.AddrPort, ed25519.PublicKey) (*kolosecure.Conn, error) { panic("test") }
			} else {
				a.hooks.dial = func(ctx context.Context, addr netip.AddrPort, pub ed25519.PublicKey) (*kolosecure.Conn, error) {
					c, err := kolosecure.Dial(ctx, addr.String(), a.id, pub, a.cfg.DHT.Secure)
					dialed = c
					return c, err
				}
				a.hooks.afterHello = func() { panic("test") }
			}
			a.mu.Unlock()
			func() {
				defer func() {
					if recover() == nil {
						t.Error("no panic")
					}
				}()
				a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop)
			}()
			if dialed != nil {
				select {
				case <-dialed.Context().Done():
				case <-time.After(time.Second):
					t.Error("the dialed connection stayed open after the hello panicked")
				}
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if len(a.slots) != 0 || len(a.dials) != 0 || len(a.helloKey) != 0 || a.dialsRunningLocked() != 0 {
				t.Fatalf("after a panic: %d slots, %d dial places, %d hello keys, %d dials", len(a.slots), len(a.dials), len(a.helloKey), a.dialsRunningLocked())
			}
		})
	}
}

// TestConnectDoesNotHoldHost checks that a Connect dial in progress does not hold its host off the dials from lookups:
// it takes no kolo-dht session there.
func TestConnectDoesNotHoldHost(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	bl := blockDials(s)
	topic := topicOf("host")
	join(t, s, topic, &JoinOptions{Lookup: true})
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer cancel()
	host := fakeAddr()
	errc := bl.connectAsync(t, ctx, s, topic, host)
	looked := make(chan struct{}, 1)
	s.mu.Lock()
	s.hooks.connect = func(ctx context.Context, _ kolodht.Record) (*kolosecure.Conn, error) {
		looked <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ts := s.topics[topic]
	s.mu.Unlock()
	s.found(topic, ts, []kolodht.Record{{Topic: topic, PublicKey: ident(t).PublicKey(), Addr: netip.AddrPortFrom(host.Addr(), host.Port()+1)}})
	select {
	case <-looked:
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup dial to the host waited for the Connect dial")
	}
	cancel()
	waitErr(t, errc)
	// Nor does a Connect place whose hello runs.
	other := fakeAddr()
	s.mu.Lock()
	s.slots[key(ident(t).PublicKey())] = &slot{topic: topic, own: other.Addr(), connect: true, reserved: true}
	s.mu.Unlock()
	s.found(topic, ts, []kolodht.Record{{Topic: topic, PublicKey: ident(t).PublicKey(), Addr: netip.AddrPortFrom(other.Addr(), other.Port()+1)}})
	select {
	case <-looked:
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup dial to the host waited for the Connect hello")
	}
}

// TestConnectDupPendingInPast checks that a Connect key known only in past at the dialed address, whose hello ended as
// a duplicate while another hello of it ran, is settled when that hello ends, as a key from a lookup is.
func TestConnectDupPendingInPast(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	topic := topicOf("dup pending")
	join(t, s, topic, &JoinOptions{Lookup: true})
	k, at := key(ident(t).PublicKey()), fakeAddr()
	sl := &slot{topic: topic, own: at.Addr(), connect: true}
	s.mu.Lock()
	s.slots[k] = sl
	s.helloKey[k] = 1
	s.past[k] = &history{addr: at, next: time.Now()}
	s.mu.Unlock()
	s.releaseConnect(k, sl, topic, at, connectProved, releaseDuplicate)
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.past[k]; h == nil || !h.dupPending || h.fails != 0 {
		t.Fatalf("past after a duplicate: %+v", h)
	}
	s.dropHelloKeyLocked(k)
	if h := s.past[k]; h == nil || h.dupPending || h.fails != 1 {
		t.Fatalf("past after the other hello: %+v", h)
	}
}

// TestConnectFailTrim checks that a backoff table past twice MaxCandidates keeps the MaxCandidates entries that end last.
func TestConnectFailTrim(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxCandidates = 16
	s := newSwarm(t, nil, nil, cfg)
	host := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 18, 0, byte(i)}) }
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range 33 {
		failLocked(s, s.endFails, netip.AddrPortFrom(host(i), 9), now.Add(time.Duration(i)*time.Hour))
	}
	if len(s.endFails) != 16 {
		t.Fatalf("%d entries, want 16", len(s.endFails))
	}
	for i := 17; i < 33; i++ {
		if f := s.endFails[netip.AddrPortFrom(host(i), 9)]; f == nil || f.fails != 1 {
			t.Fatalf("entry %d: %+v", i, f)
		}
	}
}

// TestConnectDropsBareCandidate checks that a candidate left with no topic while its key held a Connect place is
// dropped once the place is released or lost, as for a lookup dial.
func TestConnectDropsBareCandidate(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	topic := topicOf("bare")
	join(t, s, topic, &JoinOptions{Lookup: true})
	for _, lost := range []bool{false, true} {
		pub, at := ident(t).PublicKey(), fakeAddr()
		k := key(pub)
		sl := &slot{topic: topic, own: at.Addr(), connect: true}
		s.mu.Lock()
		s.slots[k] = sl
		s.cands[k] = &cand{topics: map[Topic]bool{}}
		s.mu.Unlock()
		if lost {
			f := newFake(pub)
			if _, _, err := s.admit(f, k, at, false, true, []Topic{topic}, false, generation{}); err != nil {
				t.Fatal(err)
			}
			f.peerClose(codeNormal)
		} else {
			s.releaseConnect(k, sl, topic, at, connectQuiet, releaseQuiet)
		}
		waitFor(t, 5*time.Second, "candidate dropped", func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.cands[k] == nil && s.slots[k] == nil
		})
	}
}

// TestConnectReservationRace runs the race where a second connection of the key, direct or relayed, is admitted into
// a Connect's place during its hello and then closed: the place stays the Connect's, which then fills it, so the peer
// counts in MaxConnectPeers, earns no lookup standing, never grows its windows, and the loss backs off only the pair.
func TestConnectReservationRace(t *testing.T) {
	for _, tc := range []struct {
		name     string
		viaRelay bool
	}{{"direct", false}, {"relayed", true}} {
		viaRelay := tc.viaRelay
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			topic := topicOf("reservation race")
			ia, ib := ident(t), ident(t)
			var a, b *Swarm
			var wa *watcher
			var calls atomic.Int32
			var mu sync.Mutex
			var marked []Conn
			cfg := fastConfig()
			if viaRelay {
				cfg.Relays = []Relay{{Addr: "127.0.0.1:9", PublicKey: ident(t).PublicKey()}}
			}
			cfg.Allow = func(k ed25519.PublicKey, at netip.AddrPort) bool {
				if !bytes.Equal(k, ib.PublicKey()) || at != addrOf(b.Addr()) || calls.Add(1) != 2 {
					return true
				}
				// The hello's own Allow call: a second connection of the key takes the place and is closed.
				ca, cb := securePair(t, ia, ib)
				var c Conn = ca
				if viaRelay {
					c = relayed{ca}
				}
				if ea, eb := attachBoth(t, a, b, c, cb); ea != nil || eb != nil {
					t.Errorf("Attach: %v, %v", ea, eb)
					return true
				}
				cb.CloseWithError(codeNormal, "")
				waitFor(t, 5*time.Second, "the second connection lost", func() bool { return wa.kinds(Lost) == 1 })
				return true
			}
			a = newSwarm(t, nil, ia, cfg)
			bcfg := fastConfig()
			bcfg.HelloTimeout = 10 * time.Second
			b = newSwarm(t, nil, ib, bcfg)
			b.hooks.quick.Store(int64(5 * time.Second))
			wa = watch(t, a)
			a.mu.Lock()
			a.hooks.grow = func(c Conn) {
				mu.Lock()
				marked = append(marked, c)
				mu.Unlock()
			}
			a.mu.Unlock()
			join(t, a, topic, &JoinOptions{Lookup: true})
			join(t, b, topic, &JoinOptions{Lookup: true})
			if err := a.Connect(testCtx(t, 20*time.Second), topic, ib.PublicKey(), addrOf(b.Addr()), loop); err != nil {
				t.Fatalf("Connect: %v", err)
			}
			p := wa.wait(t, ib.PublicKey())
			if !p.Direct() || !p.Outbound() || p.Addr() != addrOf(b.Addr()) {
				t.Fatalf("peer: direct %v, outbound %v, addr %v", p.Direct(), p.Outbound(), p.Addr())
			}
			mu.Lock()
			for _, c := range marked {
				if c == p.Conn() {
					t.Error("the Connect connection was marked for window growth")
				}
			}
			mu.Unlock()
			k := key(ib.PublicKey())
			a.mu.Lock()
			defer a.mu.Unlock()
			places := 0
			for _, sl := range a.slots {
				if sl.connect {
					places++
				}
			}
			if sl := a.slots[k]; sl == nil || !sl.connect || sl.reserved || sl.peer != p || places != 1 {
				t.Fatalf("place %+v, Connect places %d", sl, places)
			}
			// With Config.Relays, past may hold the key's relayed mark, never a backoff or standing.
			h := a.past[k]
			if a.standingLocked(k) != -1 || h != nil && (h.fails != 0 || h.connected || h.next.After(time.Now())) || len(a.endFails) != 0 || len(a.hostFloor) != 1 || len(a.pairFails) != 1 {
				t.Fatalf("standing %d, past %+v, address entries %d, host entries %d, pair entries %d", a.standingLocked(k), a.past[k], len(a.endFails), len(a.hostFloor), len(a.pairFails))
			}
		})
	}
}

// TestAdmitForReservation checks that a connection Connect dialed enters only its own reservation.
func TestAdmitForReservation(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	topic := topicOf("reservation")
	join(t, s, topic, &JoinOptions{Lookup: true})
	pub := ident(t).PublicKey()
	k := key(pub)
	res := &slot{topic: topic, connect: true, reserved: true}
	if _, code, err := s.admitFor(newFake(pub), k, fakeAddr(), false, true, []Topic{topic}, false, generation{}, res); !errors.Is(err, ErrDuplicate) || code != codeDuplicate {
		t.Fatalf("admit without the reservation: %v, code %d", err, code)
	}
	s.mu.Lock()
	gone := s.slots[k] == nil
	s.slots[k] = res
	s.mu.Unlock()
	if !gone {
		t.Fatal("a refused connection made a place")
	}
	if _, _, err := s.admitFor(newFake(pub), k, fakeAddr(), false, true, []Topic{topic}, false, generation{}, res); err != nil {
		t.Fatalf("admit into the reservation: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.slots[k] != res || res.peer == nil {
		t.Fatal("the connection did not fill the reservation")
	}
}

// TestConnectVouchedAddress checks that a failure after the key proved itself charges the key's own backoff only at an
// address lookups vouched for, its candidate's or past's, and only the pair anywhere else.
func TestConnectVouchedAddress(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	topic := topicOf("vouched")
	join(t, s, topic, &JoinOptions{Lookup: true})
	for _, tc := range []struct {
		name      string
		cand      bool
		vouched   netip.AddrPort // zero: no history
		sameAddr  bool
		chargeKey bool
	}{
		{"candidate here", true, fakeAddr(), true, true},
		{"candidate elsewhere", true, fakeAddr(), false, false},
		{"past here", false, fakeAddr(), true, true},
		{"past elsewhere", false, fakeAddr(), false, false},
		{"past with no address", false, netip.AddrPort{}, false, false},
		{"unknown key", false, netip.AddrPort{}, false, false},
		{"no address on either side", false, netip.AddrPort{}, true, false},
	} {
		pub := ident(t).PublicKey()
		k, at := key(pub), fakeAddr()
		if tc.sameAddr {
			at = tc.vouched
		}
		sl := &slot{topic: topic, own: at.Addr(), connect: true}
		s.mu.Lock()
		s.slots[k] = sl
		switch {
		case tc.cand:
			s.cands[k] = &cand{rec: kolodht.Record{Topic: elsewhere, PublicKey: pub, Addr: tc.vouched}, topics: map[Topic]bool{elsewhere: true}}
		case tc.name == "past with no address", tc.name == "no address on either side":
			s.past[k] = &history{next: time.Now()}
		case tc.vouched.IsValid():
			s.past[k] = &history{addr: tc.vouched, next: time.Now()}
		}
		s.mu.Unlock()
		s.releaseConnect(k, sl, topic, at, connectProved, releaseFailed)
		s.mu.Lock()
		h := s.historyLocked(k)
		charged := h != nil && h.fails == 1
		pr := backingOff(s.pairFails, pair{k, at}, time.Now())
		s.mu.Unlock()
		if charged != tc.chargeKey || pr == tc.chargeKey {
			t.Errorf("%s: key charged %v, pair backoff %v", tc.name, charged, pr)
		}
	}
}

// TestConnectLeaveDuringHello checks that Leave of the topic during the hello ends Connect with ErrRefused and grows no
// backoff.
func TestConnectLeaveDuringHello(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("leave during hello")
	ib := ident(t)
	var a, b *Swarm
	var calls atomic.Int32
	cfg := fastConfig()
	cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool {
		if bytes.Equal(k, ib.PublicKey()) && calls.Add(1) == 2 {
			a.mu.Lock()
			n := len(a.dials)
			a.mu.Unlock()
			if n != 0 {
				t.Error("the proved dial still holds its dial place during the hello")
			}
			a.Leave(topic)
		}
		return true
	}
	a = newSwarm(t, nil, nil, cfg)
	b = newSwarm(t, nil, ib, nil)
	join(t, a, topic, &JoinOptions{Lookup: true})
	join(t, b, topic, &JoinOptions{Lookup: true})
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); !errors.Is(err, errTopicLeft) {
		t.Fatalf("Connect: %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.slots) != 0 || len(a.past) != 0 || len(a.pairFails) != 0 || len(a.endFails) != 0 || len(a.hostFloor) != 0 {
		t.Fatalf("after Leave: %d slots, %d past, %d pairs, %d addresses, %d hosts", len(a.slots), len(a.past), len(a.pairFails), len(a.endFails), len(a.hostFloor))
	}
}

// TestConnectSharedHost checks that a peer naming a false key at another port of a live host cannot hold off a key
// lookups vouched for at that host: neither the false dial in progress nor its failure stands in its way, while an
// address no lookup vouched for waits.
func TestConnectSharedHost(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxConnecting = 8
	s := newSwarm(t, nil, nil, cfg)
	topic := topicOf("shared host")
	join(t, s, topic, &JoinOptions{Lookup: true})
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer cancel()
	hostIP := fakeAddr().Addr()
	falseAt, honestAt := netip.AddrPortFrom(hostIP, 9), netip.AddrPortFrom(hostIP, 4000)
	release := make(chan struct{})
	started := make(chan netip.AddrPort, 4)
	s.hooks.dial = func(ctx context.Context, addr netip.AddrPort, _ ed25519.PublicKey) (*kolosecure.Conn, error) {
		started <- addr
		if addr == falseAt {
			select {
			case <-release:
				return nil, errors.New("no answer")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	honest := ident(t).PublicKey()
	s.mu.Lock()
	s.past[key(honest)] = &history{addr: honestAt}
	s.mu.Unlock()
	falseDone := make(chan error, 1)
	falseKey := ident(t).PublicKey()
	go func() { falseDone <- s.Connect(ctx, topic, falseKey, falseAt, netip.Addr{}) }()
	<-started
	try := func(pub ed25519.PublicKey, at netip.AddrPort, wantDial bool) {
		t.Helper()
		cctx, ccancel := context.WithCancel(ctx)
		errc := make(chan error, 1)
		go func() { errc <- s.Connect(cctx, topic, pub, at, netip.Addr{}) }()
		select {
		case got := <-started:
			if !wantDial || got != at {
				t.Fatalf("dial to %v, want none", got)
			}
			ccancel()
			<-errc
		case err := <-errc:
			ccancel()
			if wantDial || !errors.Is(err, ErrWait) {
				t.Fatalf("Connect to %v: %v", at, err)
			}
		}
	}
	try(honest, honestAt, true)
	try(ident(t).PublicKey(), netip.AddrPortFrom(hostIP, 4001), false)
	close(release)
	if err := <-falseDone; !errors.Is(err, ErrLost) {
		t.Fatalf("false dial: %v", err)
	}
	try(honest, honestAt, true)
	try(ident(t).PublicKey(), netip.AddrPortFrom(hostIP, 4001), false)
	// The address that gave no answer backs off every key lookups did not find there, past the host's wait too, but
	// not one they found there.
	s.mu.Lock()
	delete(s.hostFloor, hostIP)
	s.mu.Unlock()
	try(ident(t).PublicKey(), falseAt, false)
	again := ident(t).PublicKey()
	s.mu.Lock()
	s.past[key(again)] = &history{addr: falseAt}
	s.mu.Unlock()
	try(again, falseAt, true)
	// A lookup dial in progress at the host holds off only addresses no lookup vouched for.
	s.mu.Lock()
	s.hostFloor = map[netip.Addr]time.Time{}
	s.slots[key(ident(t).PublicKey())] = &slot{topic: topic, own: hostIP}
	s.mu.Unlock()
	try(honest, honestAt, true)
	try(ident(t).PublicKey(), netip.AddrPortFrom(hostIP, 4002), false)
}

// TestConnectUnprovedDialHoldsNoSlot checks that a Connect dial to a false address for an honest key holds no slot of
// that key: a Connect to its real address and a lookup dial of it both go on while the false dial runs.
func TestConnectUnprovedDialHoldsNoSlot(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("unproved")
	a, b, wa, _ := connectPair(t, nil, nil, topic)
	falseAt := fakeAddr()
	a.hooks.dial = func(ctx context.Context, addr netip.AddrPort, pub ed25519.PublicKey) (*kolosecure.Conn, error) {
		if addr == falseAt {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return kolosecure.Dial(ctx, addr.String(), a.id, pub, a.cfg.DHT.Secure)
	}
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer cancel()
	falseDone := make(chan error, 1)
	go func() { falseDone <- a.Connect(ctx, topic, b.PublicKey(), falseAt, netip.Addr{}) }()
	waitFor(t, 5*time.Second, "the false dial", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.dials[pair{key(b.PublicKey()), falseAt}] != nil
	})
	a.mu.Lock()
	held := a.slots[key(b.PublicKey())] != nil
	a.mu.Unlock()
	if held {
		t.Fatal("an unproved dial holds a slot of the key")
	}
	if err := a.Connect(testCtx(t, 5*time.Second), topic, b.PublicKey(), falseAt, netip.Addr{}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("the same key and address again: %v", err)
	}
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); err != nil {
		t.Fatalf("Connect to the real address during the false dial: %v", err)
	}
	wa.wait(t, b.PublicKey())
	cancel()
	if err := waitErr(t, falseDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("false dial: %v", err)
	}

	looked := make(chan struct{}, 1)
	c := newSwarm(t, nil, nil, nil)
	join(t, c, topic, &JoinOptions{Lookup: true})
	bl := blockDials(c)
	c.mu.Lock()
	c.hooks.connect = func(ctx context.Context, _ kolodht.Record) (*kolosecure.Conn, error) {
		looked <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ts := c.topics[topic]
	c.mu.Unlock()
	cctx, ccancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer ccancel()
	honest := ident(t).PublicKey()
	errc := make(chan error, 1)
	go func() { errc <- c.Connect(cctx, topic, honest, fakeAddr(), netip.Addr{}) }()
	<-bl.started
	c.found(topic, ts, []kolodht.Record{{Topic: topic, PublicKey: honest, Addr: fakeAddr()}})
	select {
	case <-looked:
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup dial waited for the unproved Connect dial of the key")
	}
	ccancel()
	waitErr(t, errc)
}

// TestConnectReachableCGNAT checks that CGNAT is a scope of its own: a peer in it cannot point the swarm into a private
// range, nor the reverse, while each passes its own, as loopback and link-local do.
func TestConnectReachableCGNAT(t *testing.T) {
	for _, tc := range []struct {
		from, addr string
		want       bool
	}{
		{"100.100.1.1", "192.168.1.1", false},
		{"100.100.1.1", "10.0.0.1", false},
		{"100.100.1.1", "100.64.0.9", true},
		{"192.168.1.1", "100.64.0.9", false},
		{"192.168.1.1", "10.0.0.1", true},
		{"172.16.0.1", "192.168.1.1", true},
		{"100.100.1.1", "198.18.0.1", true},
		{"100.100.1.1", "127.0.0.1", false},
		{"127.0.0.1", "100.64.0.9", false},
		{"", "100.64.0.9", false},
		{"", "198.18.0.1", true},
		{"169.254.1.1", "169.254.2.2", true},
		{"169.254.1.1", "192.168.1.1", false},
	} {
		var from netip.Addr
		if tc.from != "" {
			from = netip.MustParseAddr(tc.from)
		}
		if got := reachableFrom(from, connectScope)(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("from %q to %s: %v", tc.from, tc.addr, got)
		}
	}
}

// TestConnectRefusedKeyRefunds checks that a key kolo-secure refuses before sending anything gives its dial start
// back, so repeating it cannot empty the dial budget of other calls.
func TestConnectRefusedKeyRefunds(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("refund")
	cfg := fastConfig()
	cfg.MaxConnecting = 2
	cfg.RetryMin, cfg.RetryMax = time.Minute, time.Minute
	a, b := newSwarm(t, nil, nil, cfg), newSwarm(t, nil, nil, nil)
	join(t, a, topic, &JoinOptions{Lookup: true})
	join(t, b, topic, &JoinOptions{Lookup: true})
	smallOrder := make(ed25519.PublicKey, ed25519.PublicKeySize)
	smallOrder[0] = 1
	for range 4 {
		if err := a.Connect(testCtx(t, 5*time.Second), topic, smallOrder, addrOf(b.Addr()), loop); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("small-order key: %v", err)
		}
	}
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); err != nil {
		t.Fatalf("Connect after refused keys: %v", err)
	}
	a.mu.Lock()
	a.connectTokens = float64(a.cfg.MaxConnecting)
	a.mu.Unlock()
	a.endDial(pair{key(smallOrder), addrOf(b.Addr())}, connectQuiet, true)
	a.mu.Lock()
	tokens := a.connectTokens
	a.mu.Unlock()
	if tokens != float64(a.cfg.MaxConnecting) {
		t.Fatalf("a refund filled the bucket past MaxConnecting: %v", tokens)
	}
}

// TestConnectPlacesCount checks that a Connect dial whose key has not proved itself counts in MaxPeers for the other
// ways in: an admission, a hello and a lookup dial.
func TestConnectPlacesCount(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxPeers, cfg.MaxInbound, cfg.MaxConnectPeers = 2, 1, 1
	s := newSwarm(t, nil, nil, cfg)
	bl := blockDials(s)
	topic, spare := topicOf("places"), topicOf("places spare")
	join(t, s, topic, &JoinOptions{Lookup: true})
	join(t, s, spare, &JoinOptions{Lookup: true}) // an empty topic, so only MaxPeers refuses
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer cancel()
	errc := bl.connectAsync(t, ctx, s, topic, fakeAddr())
	in := ident(t).PublicKey()
	if _, _, err := s.admit(newFake(in), key(in), fakeAddr(), false, true, []Topic{topic}, false, generation{}); err != nil {
		t.Fatal(err)
	}
	other := ident(t).PublicKey()
	if _, code, err := s.admit(newFake(other), key(other), fakeAddr(), false, true, []Topic{spare}, false, generation{}); !errors.Is(err, ErrRefused) || code != codeFull {
		t.Fatalf("admission past MaxPeers: %v, code %d", err, code)
	}
	if tk, _, ok := s.reserveHello(key(other), "test", false, true); ok {
		s.releaseHello(tk)
		t.Fatal("a hello past MaxPeers")
	}
	s.mu.Lock()
	s.hooks.connect = func(ctx context.Context, _ kolodht.Record) (*kolosecure.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ts := s.topics[spare]
	s.mu.Unlock()
	found := ident(t).PublicKey()
	s.found(spare, ts, []kolodht.Record{{Topic: spare, PublicKey: found, Addr: fakeAddr()}})
	// dialSome reserves a lookup dial's slot before it returns, so the state after it decides.
	s.dialSome()
	s.mu.Lock()
	dialed := s.slots[key(found)] != nil
	s.mu.Unlock()
	if dialed {
		t.Fatal("a lookup dial past MaxPeers")
	}
	cancel()
	waitErr(t, errc)
}

// TestConnectCloseAfterProof checks that a Connect whose swarm closes while the key proves itself returns ErrClosed.
func TestConnectCloseAfterProof(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("close after proof")
	a, b, _, _ := connectPair(t, nil, nil, topic)
	a.hooks.dial = func(ctx context.Context, addr netip.AddrPort, pub ed25519.PublicKey) (*kolosecure.Conn, error) {
		c, err := kolosecure.Dial(ctx, addr.String(), a.id, pub, a.cfg.DHT.Secure)
		a.Close()
		return c, err
	}
	if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop); !errors.Is(err, ErrClosed) {
		t.Fatalf("Connect: %v", err)
	}
}

// TestConnectReleaseInbound checks that releasing an inbound place Connect took over gives its inbound count back.
func TestConnectReleaseInbound(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	topic := topicOf("release inbound")
	join(t, s, topic, &JoinOptions{Lookup: true})
	k, at := key(ident(t).PublicKey()), fakeAddr()
	sl := &slot{topic: topic, inbound: true, reserved: true}
	s.mu.Lock()
	s.slots[k] = sl
	s.inbound++
	s.mu.Unlock()
	s.releaseConnect(k, sl, topic, at, connectQuiet, releaseQuiet)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inbound != 0 || s.slots[k] != nil {
		t.Fatalf("inbound %d, slot %v", s.inbound, s.slots[k])
	}
}

// TestConnectFloorTrim checks that the host wait table is trimmed like the backoff tables.
func TestConnectFloorTrim(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxCandidates = 16
	s := newSwarm(t, nil, nil, cfg)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range 33 {
		at := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, 1, byte(i)}), 9)
		s.chargeLocked(pair{key(ident(t).PublicKey()), at}, connectWrongKey, false, releaseFailed, now.Add(time.Duration(i)*time.Hour))
	}
	if len(s.hostFloor) != 16 {
		t.Fatalf("%d host entries, want 16", len(s.hostFloor))
	}
}

// dialsRunningLocked counts the Connect dials in progress, as reserveConnect does. Call with mu held.
func (s *Swarm) dialsRunningLocked() int {
	n := len(s.dials)
	for _, sl := range s.slots {
		if sl.reserved {
			n++
		}
	}
	return n
}

// until polls cond for up to d, for hooks that run outside the test goroutine and so must not call t.Fatal.
func until(d time.Duration, cond func() bool) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

// idle reports whether s runs no hello of key.
func idle(s *Swarm, key ed25519.PublicKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.helloKey[[32]byte(key)] == 0
}

// TestConnectCleanupKeepsLaterDial runs the interleaving where a Connect's hello ends and, before its cleanup, a later
// Connect of the same key and address takes the dial place: the cleanup must leave the later one's place.
func TestConnectCleanupKeepsLaterDial(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("cleanup")
	ib := ident(t)
	var a *Swarm
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer cancel()
	cfg := fastConfig()
	cfg.Allow = func(k ed25519.PublicKey, _ netip.AddrPort) bool {
		if bytes.Equal(k, ib.PublicKey()) && calls.Add(1) == 2 {
			cancel() // the hello ends quietly
		}
		return true
	}
	a = newSwarm(t, nil, nil, cfg)
	b := newSwarm(t, nil, ib, nil)
	join(t, a, topic, &JoinOptions{Lookup: true})
	join(t, b, topic, &JoinOptions{Lookup: true})
	pr := pair{key(ib.PublicKey()), addrOf(b.Addr())}
	var later *connectDial
	a.mu.Lock()
	a.hooks.beforeCleanup = func() {
		a.mu.Lock()
		a.hooks.beforeCleanup = nil
		a.mu.Unlock()
		d, err := a.reserveConnect(pr, topic, func() {})
		if err != nil {
			t.Errorf("the later Connect's place: %v", err)
		}
		later = d
	}
	a.mu.Unlock()
	if err := a.Connect(ctx, topic, ib.PublicKey(), pr.addr, loop); !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect: %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if later == nil || a.dials[pr] != later {
		t.Fatal("the cleanup dropped the later Connect's dial place")
	}
	delete(a.dials, pr)
}

// TestConnectReservedPlaceRelease checks that a lookup dial's release leaves a place a running Connect reserved, and
// that the Connect's release of a place it took over stops that place's lookup dials.
func TestConnectReservedPlaceRelease(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	topic := topicOf("reserved release")
	join(t, s, topic, &JoinOptions{Lookup: true})
	k, at := key(ident(t).PublicKey()), fakeAddr()
	var dialStopped, relayStopped bool
	sl := &slot{topic: topic, own: at.Addr(), reserved: true, dial: func() { dialStopped = true }, rdial: func() { relayStopped = true }}
	s.mu.Lock()
	s.slots[k] = sl
	s.cands[k] = &cand{topics: map[Topic]bool{topic: true}}
	s.mu.Unlock()
	s.release(k, sl, releaseFailed)
	s.mu.Lock()
	kept, fails := s.slots[k] == sl, s.cands[k].fails
	s.mu.Unlock()
	if !kept || fails != 0 {
		t.Fatalf("a lookup release of a reserved place: kept %v, fails %d", kept, fails)
	}
	s.releaseConnect(k, sl, topic, at, connectQuiet, releaseQuiet)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.slots[k] != nil || !dialStopped || !relayStopped {
		t.Fatalf("after Connect's release: slot %v, dial stopped %v, relay chain stopped %v", s.slots[k], dialStopped, relayStopped)
	}
	delete(s.cands, k)
}

// TestConnectOneVouchedDialPerHost checks that addresses lookups vouched for still take one dial at a time per host,
// since a server can forge records.
func TestConnectOneVouchedDialPerHost(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxConnecting = 8
	s := newSwarm(t, nil, nil, cfg)
	bl := blockDials(s)
	topic := topicOf("vouched host")
	join(t, s, topic, &JoinOptions{Lookup: true})
	hostIP := fakeAddr().Addr()
	k1, k2 := ident(t).PublicKey(), ident(t).PublicKey()
	at1, at2 := netip.AddrPortFrom(hostIP, 1), netip.AddrPortFrom(hostIP, 2)
	s.mu.Lock()
	s.past[key(k1)] = &history{addr: at1}
	s.past[key(k2)] = &history{addr: at2}
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.Connect(ctx, topic, k1, at1, netip.Addr{}) }()
	<-bl.started
	if err := s.Connect(ctx, topic, k2, at2, netip.Addr{}); !errors.Is(err, ErrWait) {
		t.Fatalf("a second vouched dial to the host: %v", err)
	}
	cancel()
	waitErr(t, errc)
}

// TestConnectClosedAtProof checks that a swarm marked closed when the key proves itself gives ErrClosed, before its
// context is canceled.
func TestConnectClosedAtProof(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("closed at proof")
	a, b, _, _ := connectPair(t, nil, nil, topic)
	a.hooks.dial = func(ctx context.Context, addr netip.AddrPort, pub ed25519.PublicKey) (*kolosecure.Conn, error) {
		c, err := kolosecure.Dial(ctx, addr.String(), a.id, pub, a.cfg.DHT.Secure)
		a.mu.Lock()
		a.closed = true // Close's first step; it cancels the swarm's context only later
		a.mu.Unlock()
		return c, err
	}
	err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), addrOf(b.Addr()), loop)
	a.mu.Lock()
	a.closed = false
	a.mu.Unlock()
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Connect: %v", err)
	}
}

// TestConnectTopicBeforeAllow checks that Connect refuses a closed swarm or a topic not joined before asking Allow.
func TestConnectTopicBeforeAllow(t *testing.T) {
	checkGoroutines(t)
	var asked atomic.Int32
	cfg := fastConfig()
	cfg.Allow = func(ed25519.PublicKey, netip.AddrPort) bool { asked.Add(1); return true }
	s := newSwarm(t, nil, nil, cfg)
	ctx := testCtx(t, 5*time.Second)
	if err := s.Connect(ctx, topicOf("not joined"), ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("topic not joined: %v", err)
	}
	// A key that already has a place is refused before any dial starts.
	bl := blockDials(s)
	topic := topicOf("joined")
	join(t, s, topic, &JoinOptions{Lookup: true})
	held := key(ident(t).PublicKey())
	s.mu.Lock()
	s.slots[held] = &slot{topic: topic, own: fakeAddr().Addr()}
	s.mu.Unlock()
	short, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := s.Connect(short, topic, held[:], fakeAddr(), netip.Addr{}); !errors.Is(err, ErrDuplicate) || len(bl.started) != 0 {
		t.Fatalf("a key with a place: %v, dials started %d", err, len(bl.started))
	}
	s.mu.Lock()
	delete(s.slots, held)
	s.mu.Unlock()
	s.Close()
	if err := s.Connect(ctx, topicOf("not joined"), ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
	if n := asked.Load(); n != 1 {
		t.Fatalf("Allow asked %d times, want once for the joined topic", n)
	}
}

// TestConnectLeaveDuringAllow checks that a topic left while Allow runs is refused as not joined when Connect reserves.
func TestConnectLeaveDuringAllow(t *testing.T) {
	checkGoroutines(t)
	topic := topicOf("leave during allow")
	var s *Swarm
	cfg := fastConfig()
	cfg.Allow = func(ed25519.PublicKey, netip.AddrPort) bool { s.Leave(topic); return true }
	s = newSwarm(t, nil, nil, cfg)
	blockDials(s)
	join(t, s, topic, &JoinOptions{Lookup: true})
	if err := s.Connect(testCtx(t, 5*time.Second), topic, ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Connect: %v", err)
	}
}

// TestConnectNoPlaces checks that with MaxInbound equal to MaxPeers, Connect has no place and is always refused.
func TestConnectNoPlaces(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxPeers, cfg.MaxInbound = 2, 2
	s := newSwarm(t, nil, nil, cfg)
	blockDials(s)
	topic := topicOf("no places")
	join(t, s, topic, &JoinOptions{Lookup: true})
	err := s.Connect(testCtx(t, 5*time.Second), topic, ident(t).PublicKey(), fakeAddr(), netip.Addr{})
	if !errors.Is(err, ErrRefused) || errors.Is(err, ErrWait) {
		t.Fatalf("Connect with no place: %v", err)
	}
}

// TestConnectHelloCountsAsDial checks that a Connect whose hello runs still counts in MaxConnecting.
func TestConnectHelloCountsAsDial(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxConnecting = 1
	s := newSwarm(t, nil, nil, cfg)
	blockDials(s)
	topic := topicOf("hello counts")
	join(t, s, topic, &JoinOptions{Lookup: true})
	k := key(ident(t).PublicKey())
	s.mu.Lock()
	s.slots[k] = &slot{topic: topic, own: fakeAddr().Addr(), connect: true, reserved: true}
	s.mu.Unlock()
	if err := s.Connect(testCtx(t, 5*time.Second), topic, ident(t).PublicKey(), fakeAddr(), netip.Addr{}); !errors.Is(err, ErrWait) {
		t.Fatalf("Connect while a hello runs at MaxConnecting 1: %v", err)
	}
	s.mu.Lock()
	delete(s.slots, k)
	s.mu.Unlock()
}

// TestConnectDeadlineBeforeProof checks that the caller's deadline during the dial backs off the address and makes the
// host wait, except at an address lookups found for the key.
func TestConnectDeadlineBeforeProof(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vouched bool
	}{{"unvouched", false}, {"vouched", true}} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			s := newSwarm(t, nil, nil, nil)
			bl := blockDials(s)
			topic := topicOf("deadline before proof")
			join(t, s, topic, &JoinOptions{Lookup: true})
			pub, at := ident(t).PublicKey(), fakeAddr()
			if tc.vouched {
				s.mu.Lock()
				s.past[key(pub)] = &history{addr: at}
				s.mu.Unlock()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			errc := make(chan error, 1)
			go func() { errc <- s.Connect(ctx, topic, pub, at, netip.Addr{}) }()
			<-bl.started
			if err := waitErr(t, errc); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Connect: %v", err)
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			_, end := s.endFails[at]
			_, host := s.hostFloor[at.Addr()]
			if end == tc.vouched || host == tc.vouched || len(s.pairFails) != 0 {
				t.Fatalf("address backoff %v, host wait %v, pairs %d", end, host, len(s.pairFails))
			}
		})
	}
}

// TestConnectLostDuplicate checks that a Connect place lost as a duplicate at an address no lookup vouched for grows
// no backoff, while another loss backs off the pair and makes the host wait.
func TestConnectLostDuplicate(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	topic := topicOf("lost duplicate")
	join(t, s, topic, &JoinOptions{Lookup: true})
	for _, tc := range []struct {
		code   uint64
		charge bool
	}{{codeDuplicate, false}, {codeNormal, true}} {
		pub, at := ident(t).PublicKey(), fakeAddr()
		k := key(pub)
		s.mu.Lock()
		s.slots[k] = &slot{topic: topic, own: at.Addr(), connect: true}
		s.mu.Unlock()
		f := newFake(pub)
		if _, _, err := s.admit(f, k, at, false, true, []Topic{topic}, false, generation{}); err != nil {
			t.Fatal(err)
		}
		f.peerClose(tc.code)
		waitFor(t, 5*time.Second, "lost", func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.slots[k] == nil
		})
		s.mu.Lock()
		_, pr := s.pairFails[pair{k, at}]
		_, host := s.hostFloor[at.Addr()]
		s.mu.Unlock()
		if pr != tc.charge || host != tc.charge {
			t.Fatalf("close code %d: pair backoff %v, host wait %v", tc.code, pr, host)
		}
	}
}

// TestConnectPendingTopicClaim checks that a hello claims the topic of a pending Connect dial of its own key only.
func TestConnectPendingTopicClaim(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	t1, t2 := topicOf("pending 1"), topicOf("pending 2")
	join(t, s, t1, &JoinOptions{Lookup: true})
	join(t, s, t2, &JoinOptions{Lookup: true})
	k, other := key(ident(t).PublicKey()), key(ident(t).PublicKey())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dials[pair{k, fakeAddr()}] = &connectDial{topic: t1, cancel: func() {}}
	s.dials[pair{other, fakeAddr()}] = &connectDial{topic: t2, cancel: func() {}}
	if got := s.foundTopicsLocked(k); len(got) != 1 || got[0] != t1 {
		t.Fatalf("topics %x", got)
	}
	clear(s.dials)
}

// TestConnectTakeoverTopic checks that a hello failing on a place Connect took over is judged by the Connect's own
// topic, not by the topic the place had: a zero or left former topic does not mute it, and a left Connect topic does.
func TestConnectTakeoverTopic(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	joined, left := topicOf("takeover joined"), topicOf("takeover left")
	join(t, s, joined, &JoinOptions{Lookup: true})
	for _, tc := range []struct {
		name        string
		place, mine Topic
		charge      bool
	}{
		{"relayed place with no topic", Topic{}, joined, true},
		{"lookup place on a topic left", left, joined, true},
		{"Connect topic left", joined, left, false},
	} {
		k, at := key(ident(t).PublicKey()), fakeAddr()
		sl := &slot{topic: tc.place, own: at.Addr(), reserved: true}
		s.mu.Lock()
		s.slots[k] = sl
		s.mu.Unlock()
		s.releaseConnect(k, sl, tc.mine, at, connectProved, releaseFailed)
		s.mu.Lock()
		_, pr := s.pairFails[pair{k, at}]
		s.mu.Unlock()
		if pr != tc.charge {
			t.Errorf("%s: pair backoff %v, want %v", tc.name, pr, tc.charge)
		}
	}
}

// TestConnectLimitBeforeWait checks that a limit refusal, which only peers leaving or a new configuration can end, is
// never ErrWait, even while the key, the address and the host are in their backoff.
func TestConnectLimitBeforeWait(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func(*Config)
	}{
		{"no Connect places", func(c *Config) { c.MaxPeers, c.MaxInbound = 2, 2 }},
		{"MaxPeers full", func(c *Config) { c.MaxPeers, c.MaxInbound, c.MaxConnectPeers = 2, 1, 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			cfg := fastConfig()
			tc.cfg(cfg)
			s := newSwarm(t, nil, nil, cfg)
			blockDials(s)
			topic := topicOf("limit before wait")
			join(t, s, topic, &JoinOptions{Lookup: true})
			if cfg.MaxConnectPeers == 1 {
				for _, inbound := range []bool{true, false} {
					p := ident(t).PublicKey()
					if _, _, err := s.admit(newFake(p), key(p), fakeAddr(), inbound, true, []Topic{topic}, false, generation{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			pub, at := ident(t).PublicKey(), fakeAddr()
			later := time.Now().Add(time.Hour)
			s.mu.Lock()
			s.past[key(pub)] = &history{fails: 1, next: later}
			s.endFails[at] = &failure{fails: 1, next: later}
			s.pairFails[pair{key(pub), at}] = &failure{fails: 1, next: later}
			s.hostFloor[at.Addr()] = later
			s.mu.Unlock()
			err := s.Connect(testCtx(t, 5*time.Second), topic, pub, at, netip.Addr{})
			if !errors.Is(err, ErrRefused) || errors.Is(err, ErrWait) {
				t.Fatalf("Connect: %v", err)
			}
		})
	}
}

// TestConnectLeaveIsNoFailure checks that Leave closing a Connect peer grows no backoff, so Join and Connect of the same
// key and address go on at once, at an address lookups found for the key and at one they did not.
func TestConnectLeaveIsNoFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vouched bool
	}{{"unvouched", false}, {"vouched", true}} {
		t.Run(tc.name, func(t *testing.T) {
			checkGoroutines(t)
			topic := topicOf("leave is no failure")
			a, b, wa, _ := connectPair(t, nil, nil, topic)
			at := addrOf(b.Addr())
			if tc.vouched {
				a.mu.Lock()
				a.past[key(b.PublicKey())] = &history{addr: at}
				a.mu.Unlock()
			}
			if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), at, loop); err != nil {
				t.Fatalf("Connect: %v", err)
			}
			wa.wait(t, b.PublicKey())
			a.Leave(topic)
			waitFor(t, 5*time.Second, "lost", func() bool { return wa.count() == 0 })
			join(t, a, topic, &JoinOptions{Lookup: true})
			if err := a.Connect(testCtx(t, 10*time.Second), topic, b.PublicKey(), at, loop); err != nil {
				t.Fatalf("Connect after Leave and Join: %v", err)
			}
		})
	}
}

// TestConnectThirdPartyDeadline runs the attack where a peer names other keys at the address lookups found for an
// honest key, with deadlines that end before those dials prove anything: the address backs off for them, never for
// the honest key there.
func TestConnectThirdPartyDeadline(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.RetryMin, cfg.RetryMax = time.Minute, time.Hour
	cfg.MaxConnecting = 8
	s := newSwarm(t, nil, nil, cfg)
	bl := blockDials(s)
	topic := topicOf("third party deadline")
	join(t, s, topic, &JoinOptions{Lookup: true})
	honest, at := ident(t).PublicKey(), fakeAddr()
	s.mu.Lock()
	s.past[key(honest)] = &history{addr: at}
	s.mu.Unlock()
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		x := ident(t).PublicKey()
		errc := make(chan error, 1)
		go func() { errc <- s.Connect(ctx, topic, x, at, netip.Addr{}) }()
		<-bl.started
		if err := waitErr(t, errc); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("third party's Connect: %v", err)
		}
		cancel()
		s.mu.Lock()
		f := s.endFails[at]
		if f == nil || !time.Now().Before(f.next) {
			s.mu.Unlock()
			t.Fatal("the third party's deadline did not back off the address")
		}
		// Past the waits, as the attacker would be, with the address's failures still counted.
		f.next = time.Time{}
		delete(s.hostFloor, at.Addr())
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.endFails[at].next = time.Now().Add(time.Hour)
	fails := s.endFails[at].fails
	s.mu.Unlock()
	if fails != 3 {
		t.Fatalf("address failures %d, want 3", fails)
	}
	ctx, cancel := context.WithCancel(testCtx(t, 10*time.Second))
	errc := make(chan error, 1)
	go func() { errc <- s.Connect(ctx, topic, honest, at, netip.Addr{}) }()
	select {
	case <-bl.started:
	case err := <-errc:
		t.Fatalf("the honest key at its vouched address: %v", err)
	}
	cancel()
	waitErr(t, errc)
}

// TestConnectNoDescriptor: a dial that finds no file descriptor for its socket is refused as a limit, charges nothing
// and does not hold the next dial back.
func TestConnectNoDescriptor(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	dials := 0
	s.hooks.dial = func(context.Context, netip.AddrPort, ed25519.PublicKey) (*kolosecure.Conn, error) {
		dials++
		return nil, fmt.Errorf("kolotransport: dial: %w", &os.SyscallError{Syscall: "socket", Err: syscall.EMFILE})
	}
	topic := topicOf("descriptors")
	join(t, s, topic, &JoinOptions{Lookup: true})
	for i := range 3 {
		addr := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", 4000+i))
		err := s.Connect(testCtx(t, 5*time.Second), topic, ident(t).PublicKey(), addr, netip.MustParseAddr("127.0.0.1"))
		if !errors.Is(err, errFull) || errors.Is(err, ErrWait) {
			t.Fatalf("Connect %d: %v, want a refusal that is no wait", i, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if dials != 3 || len(s.endFails) != 0 || len(s.pairFails) != 0 || len(s.hostFloor) != 0 {
		t.Fatalf("%d dials, backoff of %d addresses, %d pairs, %d hosts", dials, len(s.endFails), len(s.pairFails), len(s.hostFloor))
	}
}
