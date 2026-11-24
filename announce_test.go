package koloswarm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
)

// announceLog is an announce hook that records when each call started and answers from a script.
type announceLog struct {
	mu    sync.Mutex
	times []time.Time
	errs  func(n int) error
}

func (l *announceLog) hook(context.Context, kolodht.Topic) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.times = append(l.times, time.Now())
	if l.errs == nil {
		return nil
	}
	return l.errs(len(l.times))
}

func (l *announceLog) calls() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.times...)
}

func TestJoinPaced(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	var l announceLog
	s.hooks.announce = l.hook
	for i := range 40 {
		if err := s.Join(testCtx(t, 10*time.Second), topicOf(string(rune('A'+i))), &JoinOptions{Announce: true}); err != nil {
			t.Fatal(err)
		}
	}
	ts := l.calls()
	if len(ts) != 40 {
		t.Fatalf("%d announcements", len(ts))
	}
	for i := range ts {
		n := 0
		for _, u := range ts[i:] {
			if u.Sub(ts[i]) < time.Second {
				n++
			}
		}
		if n > 20 {
			t.Fatalf("%d announcements started within 1s of announcement %d; kolo-dht checks 20 a second", n, i)
		}
	}
}

func TestJoinRetriesNotStored(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	l := announceLog{errs: func(n int) error {
		if n < 3 {
			return kolodht.ErrNotStored
		}
		return nil
	}}
	s.hooks.announce = l.hook
	if err := s.Join(testCtx(t, 20*time.Second), topicOf("retry"), &JoinOptions{Announce: true}); err != nil {
		t.Fatalf("Join: %v", err)
	}
	ts := l.calls()
	if len(ts) != 3 {
		t.Fatalf("%d announcements, want 3", len(ts))
	}
	for i := 1; i < len(ts); i++ {
		if d := ts[i].Sub(ts[i-1]); d < time.Second {
			t.Errorf("retry %d came %v after the one before; kolo-dht's check budget refills each second", i, d)
		}
	}
}

func TestJoinNotStoredGivesUp(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	l := announceLog{errs: func(int) error { return kolodht.ErrNotStored }}
	s.hooks.announce = l.hook
	start := time.Now()
	err := s.Join(testCtx(t, 30*time.Second), topicOf("never"), &JoinOptions{Announce: true})
	if !errors.Is(err, kolodht.ErrNotStored) {
		t.Fatalf("Join: %v, want ErrNotStored", err)
	}
	if n, d := len(l.calls()), time.Since(start); n != 4 || d > 15*time.Second {
		t.Fatalf("%d announcements in %v, want 4 in under 15s", n, d)
	}

	// Leave during the wait ends Join at once.
	done := make(chan error, 1)
	go func() { done <- s.Join(testCtx(t, 30*time.Second), topicOf("left"), &JoinOptions{Announce: true}) }()
	waitFor(t, 5*time.Second, "the first announcement", func() bool { return len(l.calls()) == 5 })
	s.Leave(topicOf("left"))
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Join after Leave: %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Join kept waiting after Leave")
	}
	if n := len(l.calls()); n != 5 {
		t.Fatalf("%d announcements in all, want 5", n)
	}
}

// TestJoinBurstNotStored joins 64 topics at once on one address, 44 past the 20 checks a second kolo-dht allows it.
func TestJoinBurstNotStored(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	srv := newServer(t)
	cfg := fastConfig()
	s := newSwarm(t, srv, nil, cfg)
	start := time.Now()
	for i := range 64 {
		ctx := testCtx(t, 30*time.Second)
		if err := s.Join(ctx, topicOf(string(rune('A'+i))), &JoinOptions{Announce: true}); err != nil {
			t.Fatalf("Join %d: %v", i+1, err)
		}
	}
	t.Logf("64 joins in %v", time.Since(start))
}
