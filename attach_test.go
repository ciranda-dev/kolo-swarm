package koloswarm

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

// securePair returns the two ends of a kolo-secure connection from a to b, made outside both swarms.
func securePair(t *testing.T, a, b *koloid.Identity) (*kolosecure.Conn, *kolosecure.Conn) {
	t.Helper()
	ctx := testCtx(t, 10*time.Second)
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", b, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	accepted := make(chan *kolosecure.Conn, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	ca, err := kolosecure.Dial(ctx, l.Addr().String(), a, b.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ca.Close() })
	cb := <-accepted
	if cb == nil {
		t.Fatal("accept failed")
	}
	return ca, cb
}

// attachPair sets up a (lookup) and b (announce) on one topic, where a never dials b's kolo-dht address.
func attachPair(t *testing.T) (a, b *Swarm, wa, wb *watcher, ia, ib *koloid.Identity) {
	t.Helper()
	srv := newServer(t)
	topic := topicOf("attach")
	ia, ib = ident(t), ident(t)
	b = newSwarm(t, srv, ib, nil)
	cfg := fastConfig()
	cfg.Allow = func(key ed25519.PublicKey, addr netip.AddrPort) bool {
		return addr != addrOf(b.Addr())
	}
	a = newSwarm(t, srv, ia, cfg)
	wa, wb = watch(t, a), watch(t, b)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitFor(t, 10*time.Second, "a found b", func() bool { return wa.kinds(Found) > 0 })
	return
}

func attachBoth(t *testing.T, a, b *Swarm, ca, cb Conn) (error, error) {
	t.Helper()
	ctx := testCtx(t, 10*time.Second)
	errb := make(chan error, 1)
	go func() { errb <- b.Attach(ctx, cb, false) }()
	return a.Attach(ctx, ca, true), <-errb
}

func TestAttachSecureConn(t *testing.T) {
	checkGoroutines(t)
	a, b, wa, wb, ia, ib := attachPair(t)
	ca, cb := securePair(t, ia, ib)
	if ea, eb := attachBoth(t, a, b, ca, cb); ea != nil || eb != nil {
		t.Fatalf("Attach: %v, %v", ea, eb)
	}
	waitFor(t, 3*time.Second, "both peers", func() bool { return wa.peer(ib.PublicKey()) != nil && wb.peer(ia.PublicKey()) != nil })
	pa := wa.peer(ib.PublicKey())
	if pa.Direct() || wb.peer(ia.PublicKey()).Direct() {
		t.Fatal("attached connection reported as direct")
	}
	if pa.Addr() != addrOf(ca.RemoteAddr()) {
		t.Fatalf("Addr = %v, want the kolo-secure peer address %v", pa.Addr(), ca.RemoteAddr())
	}
	echoOver(t, pa.Conn(), wb.peer(ia.PublicKey()).Conn())
}

func TestAttachRelayed(t *testing.T) {
	checkGoroutines(t)
	a, b, wa, wb, ia, ib := attachPair(t)
	ca, cb := securePair(t, ia, ib)
	if ea, eb := attachBoth(t, a, b, relayed{ca}, relayed{cb}); ea != nil || eb != nil {
		t.Fatalf("Attach: %v, %v", ea, eb)
	}
	waitFor(t, 3*time.Second, "both peers", func() bool { return wa.peer(ib.PublicKey()) != nil && wb.peer(ia.PublicKey()) != nil })
	pa, pb := wa.peer(ib.PublicKey()), wb.peer(ia.PublicKey())
	if pa.Direct() || pb.Direct() || pa.Addr().IsValid() || pb.Addr().IsValid() {
		t.Fatalf("relayed peer: direct %v, addr %v", pa.Direct(), pa.Addr())
	}
	echoOver(t, pa.Conn(), pb.Conn())
	// The swarm never dialed b on its own while a had only the relayed path.
	if n, _ := a.slotCounts(); n != 1 {
		t.Fatalf("a holds %d slots", n)
	}
}

func TestAttachNeverReplacesDirect(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	topic := topicOf("attach direct")
	ia, ib := ident(t), ident(t)
	a, b := newSwarm(t, srv, ia, nil), newSwarm(t, srv, ib, nil)
	wa, wb := watch(t, a), watch(t, b)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitFor(t, 10*time.Second, "direct peers", func() bool { return wa.peer(ib.PublicKey()) != nil && wb.peer(ia.PublicKey()) != nil })
	direct := wa.peer(ib.PublicKey())
	ca, cb := securePair(t, ia, ib)
	ea, eb := attachBoth(t, a, b, relayed{ca}, relayed{cb})
	if !errors.Is(ea, ErrDuplicate) || !errors.Is(eb, ErrDuplicate) {
		t.Fatalf("Attach over a direct peer: %v, %v; want ErrDuplicate on both", ea, eb)
	}
	waitFor(t, 2*time.Second, "refused attached connections closed", func() bool {
		return ca.Context().Err() != nil && cb.Context().Err() != nil
	})
	time.Sleep(200 * time.Millisecond)
	if wa.peer(ib.PublicKey()) != direct || direct.Conn().Context().Err() != nil {
		t.Fatal("direct peer replaced")
	}
}

func TestAttachErrors(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	ctx := testCtx(t, 5*time.Second)
	if err := s.Attach(ctx, nil, true); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil Conn: %v", err)
	}
	self := newFake(s.PublicKey())
	if err := s.Attach(ctx, self, true); !errors.Is(err, ErrInvalidArgument) || self.ctx.Err() == nil {
		t.Fatalf("own key: %v", err)
	}
	short := newFake(make([]byte, 31))
	if err := s.Attach(ctx, short, true); !errors.Is(err, ErrInvalidArgument) || short.ctx.Err() == nil {
		t.Fatalf("short key: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	c := newFake(ident(t).PublicKey())
	if err := s.Attach(canceled, c, true); !errors.Is(err, context.Canceled) || c.ctx.Err() == nil {
		t.Fatalf("canceled: %v", err)
	}
	// A peer that never answers: the deadline of ctx ends the hello.
	short2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	silent := newFake(ident(t).PublicKey())
	if err := s.Attach(short2, silent, true); !errors.Is(err, context.DeadlineExceeded) || silent.ctx.Err() == nil {
		t.Fatalf("deadline: %v", err)
	}
}
