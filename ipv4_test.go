package koloswarm

import (
	"crypto/ed25519"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
)

func TestNewRefusesIPv6(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 5*time.Second)
	for _, addr := range []string{"[::1]:0", "[::]:0", "[::ffff:127.0.0.1]:0", "[fe80::1%lo0]:0"} {
		if s, err := New(ctx, addr, ident(t), nil); !errors.Is(err, ErrInvalidArgument) {
			if s != nil {
				s.Close()
			}
			t.Errorf("New(%q): %v, want ErrInvalidArgument", addr, err)
		}
	}
}

func TestBootstrapRefusesIPv6(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	s := newSwarm(t, nil, nil, nil)
	ctx := testCtx(t, 5*time.Second)
	good := addrOf(srv.Addr())
	mapped := netip.AddrPortFrom(netip.AddrFrom16(good.Addr().As16()), good.Port())
	for _, a := range []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:4000"), mapped} {
		err := s.Bootstrap(ctx, []netip.AddrPort{good, a})
		if !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, kolodht.ErrInvalidArgument) {
			t.Errorf("Bootstrap with %v: %v, want ErrInvalidArgument", a, err)
		}
	}
	if err := s.Bootstrap(ctx, []netip.AddrPort{}); !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, kolodht.ErrInvalidArgument) {
		t.Fatalf("Bootstrap with an empty list: %v, want both ErrInvalidArgument", err)
	}
	if err := s.Bootstrap(ctx, []netip.AddrPort{good}); err != nil {
		t.Fatalf("Bootstrap over IPv4: %v", err)
	}
}

func TestFoundSkipsIPv6Records(t *testing.T) {
	topic := topicOf("v4")
	var asked atomic.Int32
	s := unitSwarm(t, &Config{Allow: func(_ ed25519.PublicKey, a netip.AddrPort) bool {
		if !a.Addr().Is4() {
			asked.Add(1)
		}
		return true
	}}, topic)
	v4, v6, mapped := ident(t).PublicKey(), ident(t).PublicKey(), ident(t).PublicKey()
	s.found(topic, s.topics[topic], []kolodht.Record{
		{Topic: topic, PublicKey: v4, Addr: netip.MustParseAddrPort("198.51.100.1:4000")},
		{Topic: topic, PublicKey: v6, Addr: netip.MustParseAddrPort("[2001:db8::1]:4000")},
		{Topic: topic, PublicKey: mapped, Addr: netip.MustParseAddrPort("[::ffff:198.51.100.2]:4000")},
	})
	if len(s.cands) != 1 || s.cands[key(v4)] == nil {
		t.Fatalf("%d candidates, want only the IPv4 one (IPv6 kept %v, IPv4-mapped kept %v)", len(s.cands), s.cands[key(v6)] != nil, s.cands[key(mapped)] != nil)
	}
	for {
		ev, ok := nextEvent(t, s)
		if !ok {
			break
		}
		if !ev.Addr.Addr().Is4() {
			t.Fatalf("event with a non-IPv4 address: %v", ev.Addr)
		}
	}
	if asked.Load() != 0 {
		t.Fatal("Allow saw a non-IPv4 address")
	}
}

// remoteConn gives a fake Conn a remote UDP address.
type remoteConn struct {
	*fake
	addr *net.UDPAddr
}

func (r remoteConn) RemoteAddr() net.Addr { return r.addr }

func TestAttachRefusesIPv6Remote(t *testing.T) {
	topic := topicOf("v4")
	var asked atomic.Int32
	s := unitSwarm(t, &Config{Allow: func(ed25519.PublicKey, netip.AddrPort) bool {
		asked.Add(1)
		return true
	}}, topic)
	ctx := testCtx(t, 5*time.Second)
	for _, ip := range []string{"2001:db8::1", "fe80::1"} {
		f := newFake(ident(t).PublicKey())
		err := s.Attach(ctx, remoteConn{f, &net.UDPAddr{IP: net.ParseIP(ip), Port: 9}}, true)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("Attach from %s: %v, want ErrInvalidArgument", ip, err)
		}
		if code, ok := f.code(); !ok || code != codeRefused {
			t.Errorf("Attach from %s: close code %d (%v), want %d", ip, code, ok, codeRefused)
		}
	}
	if asked.Load() != 0 {
		t.Fatal("Allow saw an IPv6 address")
	}
	if s.hellos != 0 || len(s.helloSrc) != 0 {
		t.Fatalf("hello slots held: %d, %v", s.hellos, s.helloSrc)
	}
	// net.ParseIP returns 16 bytes for an IPv4 address, as the OS does; it counts as IPv4.
	if got := remoteAddr(remoteConn{newFake(ident(t).PublicKey()), &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 9}}); got != netip.MustParseAddrPort("203.0.113.7:9") {
		t.Fatalf("remoteAddr of an IPv4 address in 16 bytes = %v", got)
	}
}

func TestDialInvalidRecordNotRetried(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	topic := topicOf("norelay")
	join(t, s, topic, &JoinOptions{Lookup: true})
	k := ident(t).PublicKey()
	s.mu.Lock()
	t0 := s.topics[topic]
	s.mu.Unlock()
	// A record that no server returned has no relay, so kolo-dht's Connect refuses it with ErrInvalidArgument.
	s.found(topic, t0, []kolodht.Record{{Topic: topic, PublicKey: k, Addr: netip.MustParseAddrPort("198.51.100.1:4000")}})
	var fails int
	var next time.Time
	waitFor(t, 5*time.Second, "the dial to end", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		c := s.cands[key(k)]
		if c == nil || s.slots[key(k)] != nil || c.next.IsZero() {
			return false
		}
		fails, next = c.fails, c.next
		return true
	})
	if fails != 0 || time.Until(next) < s.cfg.LookupInterval/2 {
		t.Fatalf("invalid record retried as a failure: %d fails, next in %v", fails, time.Until(next))
	}
}
