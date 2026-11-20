package koloswarm

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
)

func TestParseNodes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{" , ,", nil},
		{"127.0.0.1:7447", []string{"127.0.0.1:7447"}},
		{" 127.0.0.1:7447 ,seed.Example.org:7447,, 10.0.0.1:1", []string{"127.0.0.1:7447", "seed.example.org:7447", "10.0.0.1:1"}},
		{"127.0.0.1:7447,127.0.0.1:7447,SEED.example.org:65535,seed.example.org:65535", []string{"127.0.0.1:7447", "seed.example.org:65535"}},
		{"node-1.example.:80", []string{"node-1.example.:80"}},
		{"localhost:7447", []string{"localhost:7447"}},
		{"123.example.org:1", []string{"123.example.org:1"}},
	} {
		got, err := ParseNodes(tc.in)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("ParseNodes(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestParseNodesRefuses(t *testing.T) {
	for _, in := range []string{
		"127.0.0.1",
		"127.0.0.1:",
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"127.0.0.1:07447",
		"127.0.0.1:+7447",
		"127.0.0.1:x",
		"[::1]:7447",
		"::1:7447",
		"[2001:db8::1]:7447",
		"[::ffff:127.0.0.1]:7447",
		"::ffff:127.0.0.1:7447",
		"[fe80::1%lo0]:7447",
		"0.0.0.0:7447",
		"0.1.2.3:7447",
		"224.0.0.1:7447",
		"240.0.0.1:7447",
		"255.255.255.255:7447",
		"1.2.3:7447",
		"300.1.1.1:7447",
		"a.example.123:1",
		"-seed.example.org:7447",
		"seed..example.org:7447",
		"seed_1.example.org:7447",
		"127.0.0.1%lo0:7447",
		strings.Repeat("a", 64) + ".org:7447",
		strings.Repeat("abcdefghi.", 26) + "org:7447",
		"127.0.0.1:7447,nope",
	} {
		if got, err := ParseNodes(in); !errors.Is(err, ErrInvalidArgument) || got != nil {
			t.Errorf("ParseNodes(%q) = %q, %v; want ErrInvalidArgument", in, got, err)
		}
	}
	for _, in := range []string{"[::1]:7447", "::1:7447", "[::ffff:127.0.0.1]:7447", "::ffff:127.0.0.1:7447", "2001:db8::1"} {
		if _, err := ParseNodes(in); err == nil || !strings.Contains(err.Error(), "IPv4 only") {
			t.Errorf("ParseNodes(%q): %v does not say IPv4 only", in, err)
		}
	}
	if _, err := ParseNodes("127.0.0.1:1, 10.0.0.1:0"); err == nil || !strings.Contains(err.Error(), "bootstrap node 2") {
		t.Errorf("error %v does not name entry 2", err)
	}
}

func TestParseNodesLimit(t *testing.T) {
	var list []string
	for i := range maxNodes {
		list = append(list, fmt.Sprintf("10.0.0.%d:7447", i+1))
	}
	if got, err := ParseNodes(strings.Join(list, ",")); err != nil || len(got) != maxNodes {
		t.Fatalf("%d nodes: %d, %v", maxNodes, len(got), err)
	}
	if _, err := ParseNodes(strings.Join(append(list, "10.0.1.1:7447"), ",")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("%d nodes: %v, want ErrInvalidArgument", maxNodes+1, err)
	}
	// Duplicates do not count, and an invalid entry after many duplicates is still found.
	dups := strings.Repeat("10.0.0.1:7447,", 1000)
	if got, err := ParseNodes(dups); err != nil || len(got) != 1 {
		t.Fatalf("duplicates: %q, %v", got, err)
	}
	if _, err := ParseNodes(dups + "[::1]:1"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("IPv6 after duplicates: %v", err)
	}
}

func TestConfigBootstrapNodes(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 5*time.Second)
	for _, nodes := range [][]string{{"[::1]:7447"}, {"127.0.0.1:0"}, {""}, {" 127.0.0.1:7447"}, {"127.0.0.1:7447,10.0.0.1:7447"}} {
		if s, err := New(ctx, "127.0.0.1:0", ident(t), &Config{BootstrapNodes: nodes}); !errors.Is(err, ErrInvalidConfig) {
			if s != nil {
				s.Close()
			}
			t.Errorf("BootstrapNodes %q: %v, want ErrInvalidConfig", nodes, err)
		}
	}
	// A comma inside one entry is a list given as one entry, not an IPv6 address.
	_, err := New(ctx, "127.0.0.1:0", ident(t), &Config{BootstrapNodes: []string{"127.0.0.1:7447,10.0.0.1:7447"}})
	if err == nil || !strings.Contains(err.Error(), "want host:port") {
		t.Errorf("a comma in one entry: %v, want host:port", err)
	}
	in := []string{"SEED.example.org:7447", "127.0.0.1:7447", "seed.example.org:7447"}
	s := newSwarm(t, nil, nil, &Config{BootstrapNodes: in})
	in[1] = "changed"
	if want := []string{"seed.example.org:7447", "127.0.0.1:7447"}; !slices.Equal(s.cfg.BootstrapNodes, want) {
		t.Fatalf("BootstrapNodes kept as %q, want %q", s.cfg.BootstrapNodes, want)
	}
}

// fakeResolver answers ip4 lookups from a map.
type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, errors.New("want ip4")
	}
	if ips, ok := f[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func useResolver(t *testing.T, r resolver) {
	old := nodeHooks.lookupIP
	nodeHooks.lookupIP = r
	t.Cleanup(func() { nodeHooks.lookupIP = old })
}

func TestBootstrapUsesConfigNodes(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	ctx := testCtx(t, 10*time.Second)
	sa := addrOf(srv.Addr())
	useResolver(t, fakeResolver{"seed.test": {sa.Addr()}})
	cfg := fastConfig()
	cfg.BootstrapNodes = []string{"missing.test:7447", fmt.Sprintf("seed.test:%d", sa.Port())}
	s := newSwarm(t, nil, nil, cfg)
	if err := s.Bootstrap(ctx, nil); err != nil {
		t.Fatalf("Bootstrap from a name: %v", err)
	}
	if n := s.node.Stats().Servers; n != 1 {
		t.Fatalf("%d servers in the table, want 1", n)
	}

	// Given servers win over the configured ones, which here would fail.
	cfg = fastConfig()
	cfg.BootstrapNodes = []string{"missing.test:7447"}
	s = newSwarm(t, nil, nil, cfg)
	if err := s.Bootstrap(ctx, []netip.AddrPort{sa}); err != nil {
		t.Fatalf("Bootstrap with servers: %v", err)
	}
	if err := s.Bootstrap(ctx, nil); !errors.Is(err, kolodht.ErrNoNodes) {
		t.Fatalf("Bootstrap from a name that does not resolve: %v, want ErrNoNodes", err)
	}
}

// An empty list that is not nil is the way to stay off the public network: an error, and no packet sent. A nil list
// uses the public entry nodes built into kolo-dht, which a test must not reach, so kolo-dht tests that path.
func TestBootstrapEmptyListFails(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 5*time.Second)
	s := newSwarm(t, nil, nil, &Config{BootstrapNodes: []string{}})
	if err := s.Bootstrap(ctx, []netip.AddrPort{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Bootstrap with an empty list and no BootstrapNodes: %v, want ErrInvalidArgument", err)
	}
}

func TestResolveNodesCaps(t *testing.T) {
	ctx := testCtx(t, 5*time.Second)
	many := func(b byte, n int) []netip.Addr {
		var out []netip.Addr
		for i := range n {
			out = append(out, netip.AddrFrom4([4]byte{10, b, 0, byte(i + 1)}))
		}
		return out
	}
	r := fakeResolver{
		"big.test":   many(1, 12),
		"mixed.test": {netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("::ffff:10.2.0.1"), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("10.2.0.1")},
	}
	useResolver(t, r)
	private := netip.MustParseAddr("10.0.0.1")
	got, err := resolveNodes(ctx, []string{"big.test:1", "mixed.test:2", "10.9.9.9:3", "10.9.9.9:3"}, private)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("10.9.9.9:3")}
	for _, ip := range many(1, maxAddrsPerName) {
		want = append(want, netip.AddrPortFrom(ip, 1))
	}
	want = append(want, netip.MustParseAddrPort("10.2.0.1:2"))
	if !slices.Equal(got, want) {
		t.Fatalf("resolved %v, want %v", got, want)
	}

	// 16 names of 8 addresses are 128; the cap keeps 64, and a literal listed last is among them.
	var nodes []string
	for i := range maxNodes - 1 {
		name := fmt.Sprintf("n%d.test", i)
		r[name] = many(byte(10+i), maxAddrsPerName)
		nodes = append(nodes, name+":7447")
	}
	nodes = append(nodes, "10.200.0.1:7447")
	got, err = resolveNodes(ctx, nodes, private)
	if err != nil || len(got) != maxBootAddrs || got[0] != netip.MustParseAddrPort("10.200.0.1:7447") {
		t.Fatalf("resolved %d addresses starting %v, %v; want %d starting with the literal", len(got), got[:1], err, maxBootAddrs)
	}

	if _, err := resolveNodes(ctx, []string{"missing.test:1"}, private); !errors.Is(err, kolodht.ErrNoNodes) {
		t.Fatalf("nothing resolved: %v, want ErrNoNodes", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := resolveNodes(cctx, []string{"missing.test:1"}, private); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v, want context.Canceled", err)
	}
}

// A name's answers count only if global or in the scope of the local address; literal entries stay as configured.
func TestResolveNodesScope(t *testing.T) {
	ctx := testCtx(t, 5*time.Second)
	var answers []netip.Addr
	for _, a := range []string{"127.0.0.2", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.168.1.9", "203.0.113.7", "8.8.8.8"} {
		answers = append(answers, netip.MustParseAddr(a))
	}
	useResolver(t, fakeResolver{"seed.test": answers})
	nodes := []string{"seed.test:7447", "10.0.0.9:1", "169.254.1.1:2"}
	for local, want := range map[string][]string{
		"127.0.0.1":   {"10.0.0.9:1", "169.254.1.1:2", "127.0.0.2:7447", "203.0.113.7:7447", "8.8.8.8:7447"},
		"192.168.1.5": {"10.0.0.9:1", "169.254.1.1:2", "10.0.0.1:7447", "100.64.0.1:7447", "192.168.1.9:7447", "203.0.113.7:7447", "8.8.8.8:7447"},
		"169.254.0.5": {"10.0.0.9:1", "169.254.1.1:2", "169.254.169.254:7447", "203.0.113.7:7447", "8.8.8.8:7447"},
		"0.0.0.0":     {"10.0.0.9:1", "169.254.1.1:2", "203.0.113.7:7447", "8.8.8.8:7447"},
	} {
		got, err := resolveNodes(ctx, nodes, netip.MustParseAddr(local))
		var gs []string
		for _, a := range got {
			gs = append(gs, a.String())
		}
		if err != nil || !slices.Equal(gs, want) {
			t.Errorf("from %s: %q, %v; want %q", local, gs, err, want)
		}
	}
}

// hangResolver answers only when its context ends.
type hangResolver struct{}

func (hangResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestResolveNodesHangingNames(t *testing.T) {
	useResolver(t, hangResolver{})
	old := nodeHooks.resolveTimeout
	nodeHooks.resolveTimeout = 200 * time.Millisecond
	t.Cleanup(func() { nodeHooks.resolveTimeout = old })
	nodes := []string{"10.0.0.9:1"}
	for i := range maxNodes - 1 {
		nodes = append(nodes, fmt.Sprintf("hang%d.test:7447", i))
	}
	start := time.Now()
	got, err := resolveNodes(testCtx(t, 30*time.Second), nodes, netip.MustParseAddr("10.0.0.1"))
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddrPort("10.0.0.9:1") {
		t.Fatalf("resolved %v, %v; want only the literal", got, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("%d hanging names took %v; want about one timeout of %v", maxNodes-1, d, nodeHooks.resolveTimeout)
	}
	// The caller's deadline ends it sooner.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	nodeHooks.resolveTimeout = time.Hour
	if _, err := resolveNodes(ctx, nodes, netip.MustParseAddr("10.0.0.1")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("with a deadline: %v, want DeadlineExceeded", err)
	}
}

// Two networks with their own entry nodes on one host never learn each other's servers, records or peers.
func TestSeparateNetworksStayApart(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t, 60*time.Second)
	topic := topicOf("one topic in two networks")
	type network struct {
		first, second *kolodht.Node
		watchers      []*watcher
		keys          map[string]bool
	}
	build := func() network {
		nw := network{first: newServer(t), second: newServer(t), keys: map[string]bool{}}
		// The first entry node of a new network calls no Bootstrap; the second one joins it.
		if err := nw.second.Bootstrap(ctx, []netip.AddrPort{addrOf(nw.first.Addr())}); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			cfg := fastConfig()
			cfg.BootstrapNodes = []string{addrOf(nw.second.Addr()).String()}
			s := newSwarm(t, nil, nil, cfg)
			if err := s.Bootstrap(ctx, nil); err != nil {
				t.Fatal(err)
			}
			nw.keys[string(s.PublicKey())] = true
			w := watch(t, s)
			s.hooks.afterLookup = func() { w.lookups.Add(1) }
			nw.watchers = append(nw.watchers, w)
		}
		return nw
	}
	a, b := build(), build()
	for _, nw := range []network{a, b} {
		for _, w := range nw.watchers {
			join(t, w.s, topic, nil)
		}
	}
	for _, nw := range []network{a, b} {
		for _, w := range nw.watchers {
			waitFor(t, 20*time.Second, "a peer in the same network", func() bool { return w.count() == 1 })
		}
	}
	// Every swarm finishes three more lookups; nothing crosses.
	var counts []func() int64
	for _, nw := range []network{a, b} {
		for _, w := range nw.watchers {
			counts = append(counts, w.lookups.Load)
		}
	}
	var base []int64
	for _, c := range counts {
		base = append(base, c())
	}
	waitFor(t, 20*time.Second, "three more lookups by every swarm", func() bool {
		for i, c := range counts {
			if c() < base[i]+3 {
				return false
			}
		}
		return true
	})
	for _, pair := range [][2]network{{a, b}, {b, a}} {
		own, other := pair[0], pair[1]
		// The second entry node verified the first in Bootstrap. The first may miss the second: on one IP both can
		// draw one node ID, and kolo-dht then moves one of them. Neither may know a server of the other network.
		if n := own.second.Stats().Servers; n != 1 {
			t.Errorf("the second entry node knows %d servers, want only the first", n)
		}
		if n := own.first.Stats().Servers; n > 1 {
			t.Errorf("the first entry node knows %d servers, want at most the second", n)
		}
		for _, w := range own.watchers {
			w.mu.Lock()
			for _, ev := range w.events {
				if other.keys[string(ev.PublicKey)] {
					t.Errorf("event %v for a key of the other network", ev.Kind)
				}
			}
			for k := range w.peers {
				if !own.keys[k] {
					t.Error("a peer from outside the network")
				}
			}
			w.mu.Unlock()
		}
		client, err := kolodht.New(ctx, "127.0.0.1:0", ident(t), &kolodht.Config{RequestTimeout: 300 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if err := client.Bootstrap(ctx, []netip.AddrPort{addrOf(own.first.Addr())}); err != nil {
			t.Fatal(err)
		}
		recs, err := client.Lookup(ctx, topic)
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != len(own.keys) {
			t.Errorf("lookup found %d records, want %d", len(recs), len(own.keys))
		}
		for _, r := range recs {
			if !own.keys[string(r.PublicKey)] {
				t.Error("lookup returned a record of the other network")
			}
		}
	}
}

func FuzzParseNodes(f *testing.F) {
	for _, s := range []string{"", "127.0.0.1:7447", "a.example:1, b.example:2", "[::1]:1", "::ffff:1.2.3.4:5", "1.2.3:4", "x:0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if strings.Contains(s, ",") {
			if _, err := parseNode(s); err == nil || err.Error() != "want host:port" {
				t.Fatalf("parseNode(%q) = %v, want host:port", s, err)
			}
		}
		got, err := ParseNodes(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidArgument) || got != nil {
				t.Fatalf("error %v with %q", err, got)
			}
			return
		}
		if len(got) > maxNodes {
			t.Fatalf("%d nodes", len(got))
		}
		again, err := ParseNodes(strings.Join(got, ","))
		if err != nil || !slices.Equal(again, got) {
			t.Fatalf("%q parses again as %q, %v", got, again, err)
		}
		for _, n := range got {
			host, _, err := net.SplitHostPort(n)
			if err != nil || strings.Contains(host, ":") {
				t.Fatalf("entry %q", n)
			}
			if ip, err := netip.ParseAddr(host); err == nil && (!ip.Is4() || !usable(ip)) {
				t.Fatalf("address %q", n)
			}
		}
	})
}

func writeNodeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nodes.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadNodes(t *testing.T) {
	p := writeNodeFile(t, "\ufeff# entry nodes of our network\r\n"+
		"127.0.0.1:7447\r\n"+
		"\r\n"+
		"   # indented comment\n"+
		"SEED.example.org:7447   # trailing comment\n"+
		"127.0.0.1:7447\n"+
		"\t10.0.0.1:1, 10.0.0.2:2\n"+
		"10.0.0.3:3")
	got, err := LoadNodes(p)
	want := []string{"127.0.0.1:7447", "seed.example.org:7447", "10.0.0.1:1", "10.0.0.2:2", "10.0.0.3:3"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("LoadNodes = %q, %v; want %q", got, err, want)
	}
	for _, content := range []string{"", "\ufeff", "# only comments\n\n#\r\n"} {
		if got, err := LoadNodes(writeNodeFile(t, content)); err != nil || got != nil {
			t.Errorf("LoadNodes(%q) = %q, %v; want nothing", content, got, err)
		}
	}
}

func TestLoadNodesRefuses(t *testing.T) {
	for _, tc := range []struct {
		content, want string
	}{
		{"127.0.0.1:7447\n[::1]:7447\n", "line 2"},
		{"127.0.0.1:7447\n\n::ffff:127.0.0.1:7447\n", "line 3"},
		{"# c\n127.0.0.1:0\n", "line 2"},
		{"127.0.0.1:7447 10.0.0.1:7447\n", "line 1"},
		{"secret-token-value\n", "line 1"},
		{"\ufeff\ufeff127.0.0.1:7447\n", "line 1"},
	} {
		_, err := LoadNodes(writeNodeFile(t, tc.content))
		if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("LoadNodes(%q): %v, want ErrInvalidArgument at %s", tc.content, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "secret") {
			t.Errorf("error %q shows the file's content", err)
		}
	}
	var lines []string
	for i := range maxNodes + 1 {
		lines = append(lines, fmt.Sprintf("10.0.0.%d:7447", i+1))
	}
	if _, err := LoadNodes(writeNodeFile(t, strings.Join(lines[:maxNodes], "\n"))); err != nil {
		t.Fatalf("%d lines: %v", maxNodes, err)
	}
	if _, err := LoadNodes(writeNodeFile(t, strings.Join(lines, "\n"))); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("%d lines: %v, want ErrInvalidArgument", maxNodes+1, err)
	}
	fits := "127.0.0.1:7447\n" + strings.Repeat("#", maxNodeFile-len("127.0.0.1:7447\n"))
	if got, err := LoadNodes(writeNodeFile(t, fits)); err != nil || len(got) != 1 {
		t.Fatalf("a file of exactly %d bytes: %q, %v", maxNodeFile, got, err)
	}
	if _, err := LoadNodes(writeNodeFile(t, fits+"#")); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("a file of %d bytes: %v", maxNodeFile+1, err)
	}
	dir := t.TempDir()
	if _, err := LoadNodes(dir); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory: %v", err)
	}
	missing := filepath.Join(dir, "missing.txt")
	if _, err := LoadNodes(missing); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), missing) {
		t.Fatalf("a missing file: %v", err)
	}
}

func FuzzParseNodeFile(f *testing.F) {
	for _, s := range []string{"", "\ufeff127.0.0.1:7447\r\n# c\n", "a.example:1 # x\n\nb.example:2,c.example:3", "[::1]:1\n", "#\n#\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseNodeFile(b)
		if err != nil {
			if !errors.Is(err, ErrInvalidArgument) || got != nil {
				t.Fatalf("error %v with %q", err, got)
			}
			return
		}
		if len(got) > maxNodes {
			t.Fatalf("%d nodes", len(got))
		}
		again, err := ParseNodes(strings.Join(got, ","))
		if err != nil || !slices.Equal(again, got) {
			t.Fatalf("%q parses again as %q, %v", got, again, err)
		}
	})
}

// TestAddressRulesMatchKoloDHT keeps usable and scopeOf, copies of kolo-dht's rules, in step with kolo-dht's Bootstrap:
// every address in the table that is unusable here is refused there, with no packet sent.
func TestAddressRulesMatchKoloDHT(t *testing.T) {
	checkGoroutines(t)
	s := newSwarm(t, nil, nil, nil)
	own := addrOf(s.Addr())
	for _, tc := range []struct {
		ip     string
		usable bool
		scope  int
	}{
		{"0.0.0.0", false, scopeInvalid},
		{"0.1.2.3", false, scopeInvalid},
		{"224.0.0.1", false, scopeInvalid},
		{"239.255.255.255", false, scopeInvalid},
		{"240.0.0.1", false, scopeInvalid},
		{"255.255.255.255", false, scopeInvalid},
		{"127.0.0.1", true, scopeLoopback},
		{"169.254.1.1", true, scopeLinkLocal},
		{"10.0.0.1", true, scopePrivate},
		{"172.16.0.1", true, scopePrivate},
		{"192.168.1.1", true, scopePrivate},
		{"100.64.0.1", true, scopePrivate},
		{"100.127.255.254", true, scopePrivate},
		{"100.128.0.1", true, scopeGlobal},
		{"198.51.100.7", true, scopeGlobal},
	} {
		ip := netip.MustParseAddr(tc.ip)
		if got := usable(ip); got != tc.usable {
			t.Errorf("usable(%s) = %v, want %v", tc.ip, got, tc.usable)
		}
		if got := scopeOf(ip); got != tc.scope {
			t.Errorf("scopeOf(%s) = %d, want %d", tc.ip, got, tc.scope)
		}
		if tc.usable {
			continue
		}
		err := s.Bootstrap(testCtx(t, 5*time.Second), []netip.AddrPort{netip.AddrPortFrom(ip, 7447)})
		if !errors.Is(err, kolodht.ErrInvalidArgument) {
			t.Errorf("kolo-dht Bootstrap of %s: %v, want ErrInvalidArgument", tc.ip, err)
		}
	}
	// A usable address that is the node's own is the one kolo-dht accepts without sending anything.
	if !usable(own.Addr()) {
		t.Fatalf("usable(%s) = false", own.Addr())
	}
	if err := s.Bootstrap(testCtx(t, 5*time.Second), []netip.AddrPort{own}); !errors.Is(err, kolodht.ErrNoNodes) {
		t.Fatalf("kolo-dht Bootstrap of the node's own address: %v, want ErrNoNodes", err)
	}
}
