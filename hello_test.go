package koloswarm

import (
	"bytes"
	"io"
	"testing"
	"time"

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
