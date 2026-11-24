package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolorelay "github.com/ciranda-dev/kolo-relay"
)

func hexKey(k ed25519.PublicKey) string { return hex.EncodeToString(k) }

func relayText(r Relay) string { return r.Addr + "@" + hexKey(r.PublicKey) }

func TestParseRelays(t *testing.T) {
	k1, k2 := ident(t).PublicKey(), ident(t).PublicKey()
	got, err := ParseRelays(" 127.0.0.1:7448@" + strings.ToUpper(hexKey(k1)) + ", ,RELAY.example.org:9@" + hexKey(k2) + ",127.0.0.1:7448@" + hexKey(k1))
	want := []Relay{{"127.0.0.1:7448", k1}, {"relay.example.org:9", k2}}
	if err != nil || len(got) != 2 || got[0].Addr != want[0].Addr || !bytes.Equal(got[0].PublicKey, k1) || got[1].Addr != want[1].Addr || !bytes.Equal(got[1].PublicKey, k2) {
		t.Fatalf("ParseRelays = %v, %v", got, err)
	}
	if got, err := ParseRelays(" , "); err != nil || got != nil {
		t.Fatalf("an empty list: %v, %v", got, err)
	}
	var many []string
	for i := range 100 {
		many = append(many, fmt.Sprintf("10.0.0.%d:1@%s", i+1, hexKey(ident(t).PublicKey())))
	}
	for _, n := range []int{17, 100} {
		if got, err := ParseRelays(strings.Join(many[:n], ",")); err != nil || len(got) != n {
			t.Fatalf("%d relays: %d, %v", n, len(got), err)
		}
		if got, err := parseRelayFile([]byte(strings.Join(many[:n], "\n"))); err != nil || len(got) != n {
			t.Fatalf("%d relays in a file: %d, %v", n, len(got), err)
		}
	}
	for _, tc := range []struct{ in, where string }{
		{"127.0.0.1:1", "relay 1"},
		{"127.0.0.1:1@" + hexKey(k1)[:62], "relay 1"},
		{"127.0.0.1:1@" + hexKey(k1) + "00", "relay 1"},
		{"127.0.0.1:1@zz" + hexKey(k1)[2:], "relay 1"},
		{"127.0.0.1:1@" + hexKey(k1) + ",[::1]:1@" + hexKey(k2), "relay 2"},
		{"[::ffff:127.0.0.1]:1@" + hexKey(k1), "relay 1"},
		{"127.0.0.1:0@" + hexKey(k1), "relay 1"},
		{"127.0.0.1:1@" + hexKey(k1) + ",127.0.0.2:1@" + hexKey(k1), "relay 2"},
		{"127.0.0.1:1@" + hexKey(k1) + ",127.0.0.1:1@" + hexKey(k2), "relay 2"},
	} {
		_, err := ParseRelays(tc.in)
		if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), tc.where) {
			t.Errorf("ParseRelays(%q): %v, want ErrInvalidArgument at %s", tc.in, err, tc.where)
		}
		if err != nil && (strings.Contains(err.Error(), hexKey(k1)[:16]) || strings.Contains(err.Error(), hexKey(k2)[:16])) {
			t.Errorf("error %q shows a key", err)
		}
	}
}

func TestLoadRelays(t *testing.T) {
	k1, k2 := ident(t).PublicKey(), ident(t).PublicKey()
	p := writeNodeFile(t, "\ufeff# relays of our network\r\n127.0.0.1:7448@"+hexKey(k1)+"\r\n\r\n  relay.example.org:9@"+hexKey(k2)+"  # second\n")
	got, err := LoadRelays(p)
	if err != nil || len(got) != 2 || got[1].Addr != "relay.example.org:9" || !bytes.Equal(got[0].PublicKey, k1) {
		t.Fatalf("LoadRelays = %v, %v", got, err)
	}
	for _, tc := range []struct{ content, where string }{
		{"127.0.0.1:1@" + hexKey(k1) + "\n[::1]:1@" + hexKey(k2) + "\n", "line 2"},
		{"# c\n\nsecret-token-value\n", "line 3"},
	} {
		_, err := LoadRelays(writeNodeFile(t, tc.content))
		if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), tc.where) || strings.Contains(err.Error(), "secret") {
			t.Errorf("LoadRelays(%q): %v, want ErrInvalidArgument at %s", tc.content, err, tc.where)
		}
	}
	line := "127.0.0.1:7448@" + hexKey(k1) + "\n"
	fits := line + strings.Repeat("#", maxNodeFile-len(line))
	if got, err := LoadRelays(writeNodeFile(t, fits)); err != nil || len(got) != 1 {
		t.Fatalf("a file of exactly %d bytes: %v, %v", maxNodeFile, got, err)
	}
	if _, err := LoadRelays(writeNodeFile(t, fits+"#")); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("a file of %d bytes: %v", maxNodeFile+1, err)
	}
	dir := t.TempDir()
	if _, err := LoadRelays(dir); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory: %v", err)
	}
	missing := filepath.Join(dir, "missing.txt")
	if _, err := LoadRelays(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing file: %v", err)
	}
}

func FuzzParseRelays(f *testing.F) {
	k := hex.EncodeToString(make([]byte, 32))
	for _, s := range []string{"", "127.0.0.1:1@" + k, "a.example:1@" + k + ", b.example:2@" + k, "[::1]:1@" + k, "x@y@z", "\ufeff#c\r\n127.0.0.1:1@" + k} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, parse := range []func(string) ([]Relay, error){ParseRelays, func(s string) ([]Relay, error) { return parseRelayFile([]byte(s)) }} {
			got, err := parse(s)
			if err != nil {
				if !errors.Is(err, ErrInvalidArgument) || got != nil {
					t.Fatalf("error %v with %v", err, got)
				}
				continue
			}
			var texts []string
			for _, r := range got {
				texts = append(texts, relayText(r))
			}
			again, err := ParseRelays(strings.Join(texts, ","))
			if err != nil || len(again) != len(got) {
				t.Fatalf("%q parses again as %v, %v", texts, again, err)
			}
		}
	})
}

func TestRelaysConfig(t *testing.T) {
	checkGoroutines(t)
	id := ident(t)
	k1, k2 := ident(t).PublicKey(), ident(t).PublicKey()
	newWith := func(relays []Relay) (*Swarm, error) {
		c := fastConfig()
		c.Relays = relays
		s, err := New(context.Background(), "127.0.0.1:0", id, c)
		if err == nil {
			t.Cleanup(func() { s.Close() })
		}
		return s, err
	}
	var many []Relay
	for i := range 100 {
		many = append(many, Relay{fmt.Sprintf("10.0.0.%d:1", i+1), ident(t).PublicKey()})
	}
	ok := Relay{"127.0.0.1:1", k1}
	for _, tc := range []struct {
		name   string
		relays []Relay
		where  string
	}{
		{"one key, two addresses", []Relay{ok, {"127.0.0.1:2", k1}}, "entry 2"},
		{"one address, two keys", []Relay{ok, {"127.0.0.1:1", k2}}, "entry 2"},
		{"IPv6", []Relay{ok, {"[::1]:1", k2}}, "entry 2"},
		{"IPv4-mapped", []Relay{{"[::ffff:127.0.0.1]:1", k2}}, "entry 1"},
		{"bare IPv6", []Relay{{"::1:1", k2}}, "entry 1"},
		{"port 0", []Relay{{"127.0.0.1:0", k2}}, "entry 1"},
		{"bad name", []Relay{{"bad_name:1", k2}}, "entry 1"},
		{"31-byte key", []Relay{ok, {"127.0.0.1:3", k2[:31]}}, "entry 2"},
		{"our own key", []Relay{ok, {"127.0.0.1:3", id.PublicKey()}}, "entry 2"},
		{"our own key after a dropped duplicate", []Relay{ok, ok, {"127.0.0.1:3", id.PublicKey()}}, "entry 3"},
	} {
		_, err := newWith(tc.relays)
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.where) {
			t.Errorf("%s: %v, want ErrInvalidConfig at %s", tc.name, err, tc.where)
		}
		if err != nil && strings.Contains(err.Error(), hexKey(k1)[:16]) {
			t.Errorf("%s: error %q shows a key", tc.name, err)
		}
	}
	if s, err := newWith(many); err != nil || len(s.relays) != 100 {
		t.Fatalf("100 relays: %v", err)
	}
	s, err := newWith([]Relay{ok, ok, {"127.0.0.1:1", k1}})
	if err != nil || len(s.relays) != 1 || len(s.cfg.Relays) != 1 {
		t.Fatalf("an exact duplicate: %v", err)
	}
	given := []Relay{{"127.0.0.1:1", bytes.Clone(k1)}}
	s, err = newWith(given)
	if err != nil {
		t.Fatal(err)
	}
	given[0].PublicKey[0] ^= 1
	if !bytes.Equal(s.relays[0].key, k1) {
		t.Fatal("the swarm shares the caller's key slice")
	}
	for _, relays := range [][]Relay{nil, {}} {
		if s, err := newWith(relays); err != nil || s.relays != nil {
			t.Fatalf("%v: %v", relays, err)
		}
	}
}

func TestRelaysExactDuplicateReservesOnce(t *testing.T) {
	checkGoroutines(t)
	var reserves atomic.Int32
	r := startRelay(t, &kolorelay.ServerConfig{AllowReserve: func(ed25519.PublicKey) bool {
		reserves.Add(1)
		return true
	}})
	a := newSwarm(t, newServer(t), nil, relayConfig(r.entry(), r.entry()))
	wa := watch(t, a)
	join(t, a, topicOf(t.Name()), &JoinOptions{Announce: true})
	waitFor(t, 20*time.Second, "held", func() bool { return wa.held(r.key) })
	if n := reserves.Load(); n != 1 {
		t.Fatalf("%d reservations for one relay listed twice", n)
	}
}

func TestRelayChangedPerRelay(t *testing.T) {
	checkGoroutines(t)
	var n1, n2 atomic.Int32
	r1 := startRelay(t, &kolorelay.ServerConfig{AllowReserve: func(ed25519.PublicKey) bool { n1.Add(1); return false }})
	r2 := startRelay(t, &kolorelay.ServerConfig{AllowReserve: func(ed25519.PublicKey) bool { n2.Add(1); return false }})
	a := newSwarm(t, newServer(t), nil, relayConfig(r1.entry(), r2.entry()))
	join(t, a, topicOf(t.Name()), &JoinOptions{Announce: true})
	waitFor(t, 30*time.Second, "both relays flapping", func() bool { return n1.Load() >= 3 && n2.Load() >= 3 })
	per := map[string]int{}
	// Every RelayChanged is queued with mu held, so holding it freezes the queue while it is read.
	a.mu.Lock()
	defer a.mu.Unlock()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		ev, err := a.events.Pop(ctx, nil)
		cancel()
		if err != nil {
			break
		}
		if ev.Kind == RelayChanged {
			if !errors.Is(ev.Err, kolorelay.ErrNotAllowed) {
				t.Fatalf("RelayChanged with %v", ev.Err)
			}
			per[string(ev.PublicKey)]++
		}
	}
	if len(per) != 2 || per[string(r1.key)] != 1 || per[string(r2.key)] != 1 {
		t.Fatalf("queued RelayChanged per relay: %v", per)
	}
}

func TestRelaysFirstDownSecondUp(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	dead := downRelay(t)
	r2 := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	cfg := func() *Config {
		c := relayConfig(dead, r2.entry())
		c.RetryMin, c.RetryMax = time.Minute, time.Hour
		return c
	}
	b := newSwarm(t, srv, nil, cfg())
	c := newSwarm(t, srv, nil, cfg())
	a := newSwarm(t, srv, nil, cfg())
	g := newGate(a)
	g.set(b.PublicKey(), refuseConn)
	g.set(c.PublicKey(), refuseConn)
	log := logRelays(a, nil)
	wa, wb := watch(t, a), watch(t, b)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitRelayed(t, wa, b.PublicKey(), r2.key)
	if got := log.to(b.PublicKey()); !slices.Equal(got, []string{string(dead.PublicKey), string(r2.key)}) {
		t.Fatalf("first chain tried %d relays, want the down one then the second", len(got))
	}
	waitFor(t, 30*time.Second, "RelayChanged for both", func() bool { return wb.sawRelay(dead.PublicKey, ErrLost) && wb.held(r2.key) })
	join(t, c, topic, &JoinOptions{Announce: true})
	waitRelayed(t, wa, c.PublicKey(), r2.key)
	if got := log.to(c.PublicKey()); !slices.Equal(got, []string{string(r2.key)}) {
		t.Fatalf("the next chain tried %d relays, want the down one skipped", len(got))
	}
}

func TestRelaysBothUp(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	r1, r2 := startRelay(t, nil), startRelay(t, nil)
	cfg := func() *Config { return relayConfig(r1.entry(), r2.entry()) }
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, cfg())
	a := newSwarm(t, srv, nil, cfg())
	newGate(a).set(b.PublicKey(), refuseConn)
	log := logRelays(a, nil)
	wa := watch(t, a)
	join(t, b, topic, nil)
	join(t, a, topic, nil)
	for _, r := range []*testRelay{r1, r2} {
		for _, s := range []*Swarm{a, b} {
			if err := rawDial(t, r.entry(), s.PublicKey()); err != nil {
				t.Fatalf("Dial through each relay: %v", err)
			}
		}
	}
	waitRelayed(t, wa, b.PublicKey(), r1.key)
	if got := log.to(b.PublicKey()); len(got) == 0 || got[0] != string(r1.key) || slices.Contains(got, string(r2.key)) {
		t.Fatal("the first chain did not stop at the first relay")
	}
}

func TestRelaysShareOne(t *testing.T) {
	checkGoroutines(t)
	r1, r2, r3 := startRelay(t, nil), startRelay(t, nil), startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, relayConfig(r3.entry(), r2.entry()))
	a := newSwarm(t, srv, nil, relayConfig(r1.entry(), r2.entry()))
	newGate(a).set(b.PublicKey(), refuseConn)
	log := logRelays(a, nil)
	wa := watch(t, a)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitRelayed(t, wa, b.PublicKey(), r2.key)
	if got := log.to(b.PublicKey()); !slices.Equal(got, []string{string(r1.key), string(r2.key)}) {
		t.Fatalf("chain tried %d relays, want the unshared one then the shared one", len(got))
	}
}

func TestRelaysShareNone(t *testing.T) {
	checkGoroutines(t)
	var mu sync.Mutex
	var connectAt time.Time
	r1 := startRelay(t, &kolorelay.ServerConfig{AllowConnect: func(_, _ ed25519.PublicKey) bool {
		mu.Lock()
		if connectAt.IsZero() {
			connectAt = time.Now()
		}
		mu.Unlock()
		return true
	}})
	r2 := startRelay(t, nil)
	a, b, wa, wb, _ := relayedPair(t, topicOf(t.Name()), relayConfig(r1.entry()), relayConfig(r2.entry()))
	var at time.Time
	waitFor(t, 30*time.Second, "Unreachable", func() bool {
		wa.mu.Lock()
		defer wa.mu.Unlock()
		for _, e := range wa.events {
			if e.Kind == Unreachable && errors.Is(e.Err, kolodht.ErrUnreachable) {
				at = time.Now()
				return true
			}
		}
		return false
	})
	waitFor(t, 30*time.Second, "the backoff growing", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		c := a.cands[key(b.PublicKey())]
		return c != nil && c.fails >= 2
	})
	mu.Lock()
	if connectAt.IsZero() || !connectAt.Before(at) {
		t.Error("Unreachable before the relay answered")
	}
	mu.Unlock()
	wa.mu.Lock()
	for _, e := range wa.events {
		if bytes.Equal(e.PublicKey, b.PublicKey()) && e.Kind != Found && e.Kind != Unreachable {
			t.Errorf("%v event for a key behind no shared relay", e.Kind)
		}
	}
	wa.mu.Unlock()
	if wa.kinds(Connected)+wb.kinds(Connected) != 0 {
		t.Fatal("connected without a shared relay")
	}
}

func TestRelaysRememberLast(t *testing.T) {
	checkGoroutines(t)
	r1 := startRelay(t, nil)
	r2 := startRelay(t, &kolorelay.ServerConfig{MaxSessionDuration: time.Second})
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, relayConfig(r2.entry()))
	a := newSwarm(t, srv, nil, relayConfig(r1.entry(), r2.entry()))
	newGate(a).set(b.PublicKey(), refuseConn)
	log := logRelays(a, nil)
	wa := watch(t, a)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	first := waitRelayed(t, wa, b.PublicKey(), r2.key)
	<-first.Conn().Context().Done()
	waitFor(t, 60*time.Second, "relayed again", func() bool {
		p := wa.peer(b.PublicKey())
		return p != nil && p != first && !p.Direct()
	})
	got := log.to(b.PublicKey())
	if len(got) < 3 || got[0] != string(r1.key) || got[1] != string(r2.key) || got[2] != string(r2.key) {
		t.Fatal("the second chain did not start at the relay that carried the key last")
	}
}

func TestRelaysThreeOrder(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	dead := downRelay(t)
	r2, r3 := startRelay(t, nil), startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	b := newSwarm(t, srv, nil, relayConfig(r3.entry()))
	a := newSwarm(t, srv, nil, relayConfig(dead, r2.entry(), r3.entry()))
	newGate(a).set(b.PublicKey(), refuseConn)
	log := logRelays(a, nil)
	wa := watch(t, a)
	join(t, b, topic, &JoinOptions{Announce: true})
	join(t, a, topic, &JoinOptions{Lookup: true})
	waitRelayed(t, wa, b.PublicKey(), r3.key)
	got := log.to(b.PublicKey())
	if i := slices.Index(got, string(r2.key)); i < 0 || slices.Index(got, string(r3.key)) != i+1 || slices.Contains(got[:i], string(r3.key)) {
		t.Fatal("the chain did not go through the second relay before the third")
	}
	a.mu.Lock()
	down := a.relays[0].down
	a.mu.Unlock()
	if down == 0 {
		t.Fatal("the dead relay is not marked down")
	}
}

func TestRelaysRenewalFailover(t *testing.T) {
	checkGoroutines(t)
	var bkey atomic.Value
	var reserved atomic.Int32
	gap := make(chan struct{})
	r1 := startRelay(t, &kolorelay.ServerConfig{ReservationLifetime: time.Second, AllowReserve: func(k ed25519.PublicKey) bool {
		if want, _ := bkey.Load().(string); want == string(k) && reserved.Add(1) > 1 {
			// Hold the renewal, so the gap lasts while the chain runs.
			<-gap
		}
		return true
	}})
	t.Cleanup(func() { close(gap) })
	r2 := startRelay(t, nil)
	srv := newServer(t)
	topic := topicOf(t.Name())
	bid := ident(t)
	bkey.Store(string(bid.PublicKey()))
	b := newSwarm(t, srv, bid, relayConfig(r1.entry(), r2.entry()))
	wb := watch(t, b)
	join(t, b, topic, &JoinOptions{Announce: true})
	waitFor(t, 30*time.Second, "r1's reservation ended", func() bool { return wb.sawRelay(r1.key, kolorelay.ErrReservationEnded) })
	c := newSwarm(t, srv, nil, relayConfig(r1.entry(), r2.entry()))
	newGate(c).set(b.PublicKey(), refuseConn)
	log := logRelays(c, nil)
	wc := watch(t, c)
	join(t, c, topic, &JoinOptions{Lookup: true})
	waitRelayed(t, wc, b.PublicKey(), r2.key)
	if got := log.to(b.PublicKey()); !slices.Equal(got, []string{string(r1.key), string(r2.key)}) {
		t.Fatalf("chain tried %d relays, want the one in its gap then the other", len(got))
	}
}
