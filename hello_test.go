package koloswarm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	"github.com/ciranda-dev/kolo-swarm/internal/hello"
)

// rawPeer connects to s directly with kolo-secure, as id, without a swarm: a test double for a remote peer.
func rawPeer(t *testing.T, s *Swarm, id *koloid.Identity) *kolosecure.Conn {
	t.Helper()
	ctx := testCtx(t, 10*time.Second)
	c, err := kolosecure.Dial(ctx, s.Addr().String(), id, s.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// sides returns an identity larger than s's key (s arbitrates) or smaller (s follows).
func sides(t *testing.T, s *Swarm, larger bool) *koloid.Identity {
	for {
		id := ident(t)
		if (bytes.Compare(id.PublicKey(), s.PublicKey()) > 0) == larger {
			return id
		}
	}
}

// replyRaw returns an arbiter's reply for gen and topics.
func replyRaw(t *testing.T, gen uint64, topics ...Topic) []byte {
	t.Helper()
	b, err := hello.EncodeReply(1, gen, rawTopics(topics))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func encodeRaw(t *testing.T, topics ...Topic) []byte {
	t.Helper()
	b, err := hello.Encode(rawTopics(topics))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// send writes b on a new stream and ends it; with read set it returns what the swarm answers.
func send(t *testing.T, c *kolosecure.Conn, b []byte, read bool) []byte {
	t.Helper()
	ctx := testCtx(t, 5*time.Second)
	st, err := c.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(b); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if !read {
		return nil
	}
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, _ := io.ReadAll(st)
	return reply
}

// answer reads the swarm's hello on c and replies with b.
func answer(t *testing.T, c *kolosecure.Conn, b []byte) []Topic {
	t.Helper()
	ctx := testCtx(t, 5*time.Second)
	st, err := c.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	b2, err := readMsg(st)
	if err != nil {
		t.Fatalf("swarm hello: %v", err)
	}
	raw, err := hello.Decode(b2)
	if err != nil {
		t.Fatalf("swarm hello: %v", err)
	}
	var got []Topic
	for _, x := range raw {
		got = append(got, Topic(x))
	}
	st.Write(b)
	st.Close()
	return got
}

func helloSwarm(t *testing.T, cfg *Config) (*Swarm, *watcher, Topic) {
	t.Helper()
	srv := newServer(t)
	s := newSwarm(t, srv, nil, cfg)
	w := watch(t, s)
	topic := topicOf("hello")
	join(t, s, topic, &JoinOptions{Announce: true})
	return s, w, topic
}

func TestHelloRejects(t *testing.T) {
	checkGoroutines(t)
	s, w, topic := helloSwarm(t, nil)
	many := make([]byte, 0, hello.MaxSize+40)
	many = append(many, 0, hello.MaxTopics+1)
	for i := range hello.MaxTopics + 1 {
		x := topicOf(string(rune('a' + i)))
		many = append(many, x[:]...)
	}
	one := encodeRaw(t, topic)
	tests := []struct {
		name    string
		payload []byte
	}{
		{"oversize", make([]byte, hello.MaxSize+1)},
		{"version 1", append([]byte{1}, one[1:]...)},
		{"33 topics", many},
		{"duplicate topic", append(append([]byte{0, 2}, topic[:]...), topic[:]...)},
		{"trailing byte", append(bytes.Clone(one), 0)},
		{"empty", nil},
	}
	for _, tt := range tests {
		c := rawPeer(t, s, sides(t, s, true))
		send(t, c, tt.payload, false)
		if code := closeCodeOf(t, c, 4*time.Second); code != codeProtocol {
			t.Errorf("%s: closed with %d, want %d", tt.name, code, codeProtocol)
		}
	}
	rone := replyRaw(t, 1, topic)
	replies := []struct {
		name    string
		payload []byte
	}{
		{"oversize", make([]byte, hello.MaxSize+1)},
		{"version 1", append([]byte{1}, rone[1:]...)},
		{"33 topics", append([]byte{0, 1}, many[1:]...)},
		{"duplicate topic", append(append([]byte{0, 1, 2}, topic[:]...), topic[:]...)},
		{"trailing byte", append(bytes.Clone(rone), 0)},
		{"empty", nil},
		{"a hello", one},
	}
	for _, tt := range replies {
		c := rawPeer(t, s, sides(t, s, false))
		answer(t, c, tt.payload)
		if code := closeCodeOf(t, c, 4*time.Second); code != codeProtocol {
			t.Errorf("reply %s: closed with %d, want %d", tt.name, code, codeProtocol)
		}
	}
	// A reply must name at least one topic.
	c := rawPeer(t, s, sides(t, s, false))
	answer(t, c, []byte{0, 1, 0})
	if code := closeCodeOf(t, c, 4*time.Second); code != codeProtocol {
		t.Errorf("empty reply: closed with %d", code)
	}
	if n := w.kinds(Connected); n != 0 {
		t.Fatalf("%d peers admitted from malformed hellos", n)
	}
}

func TestHelloSilence(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	s, w, _ := helloSwarm(t, nil)
	for _, larger := range []bool{true, false} {
		c := rawPeer(t, s, sides(t, s, larger))
		start := time.Now()
		if code := closeCodeOf(t, c, 5*time.Second); code != codeProtocol {
			t.Fatalf("silent peer closed with %d", code)
		}
		if d := time.Since(start); d < 1500*time.Millisecond {
			t.Fatalf("closed after %v, before HelloTimeout", d)
		}
	}
	if w.kinds(Connected) != 0 {
		t.Fatal("silent peer admitted")
	}
}

func TestHelloValid(t *testing.T) {
	checkGoroutines(t)
	s, w, topic := helloSwarm(t, nil)

	big := sides(t, s, true)
	c := rawPeer(t, s, big)
	reply := send(t, c, encodeRaw(t, topic, topicOf("other")), true)
	_, _, got, err := hello.DecodeReply(reply)
	if err != nil || len(got) != 1 || Topic(got[0]) != topic {
		t.Fatalf("arbiter reply %x, %v", reply, err)
	}
	waitFor(t, 3*time.Second, "peer admitted", func() bool { return w.peer(big.PublicKey()) != nil })

	small := sides(t, s, false)
	c2 := rawPeer(t, s, small)
	if mine := answer(t, c2, replyRaw(t, 1, topic)); len(mine) != 0 {
		t.Fatalf("swarm put forward %d topics it never found the peer on", len(mine))
	}
	waitFor(t, 3*time.Second, "follower admitted", func() bool { return w.peer(small.PublicKey()) != nil })
	if c.Context().Err() != nil || c2.Context().Err() != nil {
		t.Fatal("admitted connection closed")
	}
	echoOver(t, c2, w.peer(small.PublicKey()).Conn())
}

func TestNoSharedTopic(t *testing.T) {
	checkGoroutines(t)
	s, w, _ := helloSwarm(t, nil)
	stranger := topicOf("not joined")
	c := rawPeer(t, s, sides(t, s, true))
	send(t, c, encodeRaw(t, stranger), false)
	if code := closeCodeOf(t, c, 4*time.Second); code != codeRefused {
		t.Fatalf("closed with %d, want %d", code, codeRefused)
	}
	c2 := rawPeer(t, s, sides(t, s, false))
	answer(t, c2, replyRaw(t, 1, stranger))
	if code := closeCodeOf(t, c2, 4*time.Second); code != codeRefused {
		t.Fatalf("follower closed with %d, want %d", code, codeRefused)
	}
	if w.kinds(Connected) != 0 {
		t.Fatal("peer without a shared topic admitted")
	}
}

func TestFullBeforeHello(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxPeers = 1
	s, w, topic := helloSwarm(t, cfg)
	first := sides(t, s, true)
	send(t, rawPeer(t, s, first), encodeRaw(t, topic), true)
	waitFor(t, 3*time.Second, "first peer", func() bool { return w.peer(first.PublicKey()) != nil })
	c := rawPeer(t, s, sides(t, s, true))
	if code := closeCodeOf(t, c, time.Second); code != codeFull {
		t.Fatalf("closed with %d, want %d", code, codeFull)
	}
}

func TestInboundFullBeforeHello(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxPeers, cfg.MaxInbound = 4, 1
	s, w, topic := helloSwarm(t, cfg)
	first := sides(t, s, true)
	send(t, rawPeer(t, s, first), encodeRaw(t, topic), true)
	waitFor(t, 3*time.Second, "first peer", func() bool { return w.peer(first.PublicKey()) != nil })
	c := rawPeer(t, s, sides(t, s, true))
	if code := closeCodeOf(t, c, time.Second); code != codeFull {
		t.Fatalf("closed with %d, want %d", code, codeFull)
	}
}

func TestHandshakeLimits(t *testing.T) {
	checkGoroutines(t)
	cfg := fastConfig()
	cfg.MaxHandshakes, cfg.MaxHandshakesPerIP = 2, 2
	s, _, _ := helloSwarm(t, cfg)
	id := sides(t, s, true)
	rawPeer(t, s, id)
	rawPeer(t, s, id)
	waitFor(t, 2*time.Second, "two hellos in progress", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.hellos == 2
	})
	third := rawPeer(t, s, id)
	if code := closeCodeOf(t, third, time.Second); code != codeFull {
		t.Fatalf("third hello from one key closed with %d, want %d", code, codeFull)
	}
	other := rawPeer(t, s, sides(t, s, true))
	if code := closeCodeOf(t, other, time.Second); code != codeFull {
		t.Fatalf("hello past MaxHandshakes closed with %d, want %d", code, codeFull)
	}
}

func manyTopics(name string, n int) []Topic {
	var out []Topic
	for i := range n {
		out = append(out, topicOf(fmt.Sprintf("%s %d", name, i)))
	}
	return out
}

// sharedPair starts two swarms, a (the arbiter) and b, that both joined every topic and know each other on all of
// them before their first dial.
func sharedPair(t *testing.T, topics []Topic) (a, b *Swarm, wa, wb *watcher) {
	t.Helper()
	srv := newServer(t)
	ida, idb := identPair(t)
	a, b = newSwarm(t, srv, ida, nil), newSwarm(t, srv, idb, nil)
	gate := make(chan struct{})
	for _, s := range []*Swarm{a, b} {
		s.hooks.connect = func(ctx context.Context, rec kolodht.Record) (*kolosecure.Conn, error) {
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return s.node.Connect(ctx, rec)
		}
	}
	wa, wb = watch(t, a), watch(t, b)
	for _, s := range []*Swarm{a, b} {
		for _, x := range topics {
			join(t, s, x, nil)
		}
	}
	knows := func(s, o *Swarm) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		c := s.cands[key(o.PublicKey())]
		return c != nil && len(c.topics) == len(topics)
	}
	waitFor(t, 30*time.Second, "both swarms to know each other on every topic", func() bool { return knows(a, b) && knows(b, a) })
	close(gate)
	waitFor(t, 15*time.Second, "the connection", func() bool { return wa.peer(b.PublicKey()) != nil && wb.peer(a.PublicKey()) != nil })
	return a, b, wa, wb
}

// TestHelloManySharedTopics: the hello and the reply carry 32 topics, and both sides still count the peer on all 40.
func TestHelloManySharedTopics(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	a, b, wa, wb := sharedPair(t, manyTopics("shared", 40))
	for _, p := range []*Peer{wa.peer(b.PublicKey()), wb.peer(a.PublicKey())} {
		if n := len(p.Topics()); n != 40 {
			t.Errorf("a peer counted on %d topics, want 40", n)
		}
	}
}

// TestLeaveKeepsKnownPeer: leaving every topic a hello listed keeps a peer that our lookups found on others.
func TestLeaveKeepsKnownPeer(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	a, b, _, wb := sharedPair(t, manyTopics("leave", 40))
	p := wb.peer(a.PublicKey())
	all := p.Topics()
	for _, x := range all[:32] {
		b.Leave(x)
	}
	stable(t, 5*time.Second, 2*time.Second, "the peer to stay with 8 topics", func() bool {
		got := p.Topics()
		return p.Conn().Context().Err() == nil && len(got) == 8 && slices.Equal(got, all[32:])
	})
}

// TestLeaveRefillsFromLookups: a peer whose list empties on Leave keeps its place if our lookups found it on another topic.
func TestLeaveRefillsFromLookups(t *testing.T) {
	checkGoroutines(t)
	x, y := topicOf("x"), topicOf("y")
	s := placeSwarm(t, nil, x, y)
	k, f := seat(t, s, 0, false, x)
	s.mu.Lock()
	s.cands[k] = &cand{topics: map[Topic]bool{x: true, y: true}}
	s.mu.Unlock()
	s.Leave(x)
	time.Sleep(100 * time.Millisecond)
	if code, closed := f.code(); closed {
		t.Fatalf("closed with code %d", code)
	}
	s.mu.Lock()
	got := s.slots[k].peer.topics
	s.mu.Unlock()
	if len(got) != 1 || got[0] != y {
		t.Fatalf("topics %v, want y", got)
	}
	s.Leave(y)
	if code, ok := f.code(); !ok || code != codeNormal {
		t.Fatalf("code %d, %v after the last topic was left", code, ok)
	}
}

func TestReplyOverWireCap(t *testing.T) {
	kept := manyTopics("kept", 40)
	listed := rawTopics([]Topic{kept[35], kept[7], kept[20]})
	got := replyTopics(kept, listed)
	if len(got) != hello.MaxTopics {
		t.Fatalf("%d topics, want %d", len(got), hello.MaxTopics)
	}
	if got[0] != kept[7] || got[1] != kept[20] || got[2] != kept[35] {
		t.Fatalf("the topics the hello listed do not come first: %v", got[:3])
	}
	if got := replyTopics(kept[:5], nil); len(got) != 5 {
		t.Fatalf("a short list changed: %v", got)
	}
}

// TestRedialAfterPeerLeft: a peer that left some topics is redialed through its record of a topic it still announces,
// and the records it left do not count as failures of its key.
func TestRedialAfterPeerLeft(t *testing.T) {
	longTest(t)
	checkGoroutines(t)
	srv := newServer(t)
	a := newSwarm(t, srv, nil, nil)
	cfg := fastConfig()
	cfg.LookupInterval = time.Hour
	b := newSwarm(t, srv, nil, cfg)
	wa, wb := watch(t, a), watch(t, b)
	topics := manyTopics("redial", 3)
	for _, x := range topics {
		join(t, a, x, &JoinOptions{Announce: true})
	}
	// A second peer on the live topic, so that b tries the topics a left first.
	join(t, newSwarm(t, srv, nil, nil), topics[2], &JoinOptions{Announce: true})
	// The last record b keeps is of a topic a leaves.
	for _, x := range []Topic{topics[2], topics[0], topics[1]} {
		join(t, b, x, &JoinOptions{Lookup: true})
	}
	waitFor(t, 15*time.Second, "the connections", func() bool { return wb.peer(a.PublicKey()) != nil && wb.count() == 2 })
	waitFor(t, 15*time.Second, "b to know a on 3 topics", func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		c := b.cands[key(a.PublicKey())]
		return c != nil && len(c.topics) == 3
	})
	a.Leave(topics[0])
	a.Leave(topics[1])
	old := wb.peer(a.PublicKey())
	wa.peer(b.PublicKey()).Conn().CloseWithError(codeNormal, "")
	waitFor(t, 5*time.Second, "the connection to end", func() bool { return wb.peer(a.PublicKey()) != old })
	waitFor(t, 30*time.Second, "b to reconnect through the topic a still announces", func() bool { return wb.peer(a.PublicKey()) != nil })
	b.mu.Lock()
	defer b.mu.Unlock()
	if f := b.cands[key(a.PublicKey())].fails; f != 1 {
		t.Fatalf("a has %d failures, want only the one of its lost connection", f)
	}
}

// TestRotateRounds: only the dial that ends a round of a key's records counts as its failure.
func TestRotateRounds(t *testing.T) {
	checkGoroutines(t)
	x, y := topicOf("x"), topicOf("y")
	s := placeSwarm(t, nil, x, y)
	k := key(ident(t).PublicKey())
	rx := kolodht.Record{Topic: x, PublicKey: k[:], Addr: fakeAddr()}
	ry := kolodht.Record{Topic: y, PublicKey: k[:], Addr: fakeAddr()}
	s.mu.Lock()
	s.cands[k] = &cand{rec: ry, recs: map[Topic]kolodht.Record{x: rx, y: ry}, topics: map[Topic]bool{x: true, y: true}}
	s.mu.Unlock()
	for round := range 2 {
		if !s.rotate(k, x, rx) {
			t.Fatalf("round %d: the first record failed and the second is not suspect", round)
		}
		if s.rotate(k, y, ry) {
			t.Fatalf("round %d: every record failed, and the round did not end", round)
		}
	}
}
