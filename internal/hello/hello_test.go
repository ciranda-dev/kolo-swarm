package hello

import (
	"bytes"
	"errors"
	"testing"
)

func topic(b byte) [32]byte {
	var t [32]byte
	t[0] = b
	return t
}

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 2, MaxTopics} {
		var in [][32]byte
		for i := range n {
			in = append(in, topic(byte(i)))
		}
		b, err := Encode(in)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > MaxHelloSize {
			t.Fatalf("%d topics: %d bytes, over %d", n, len(b), MaxHelloSize)
		}
		out, err := Decode(b)
		if err != nil {
			t.Fatalf("%d topics: %v", n, err)
		}
		if len(out) != n {
			t.Fatalf("decoded %d topics, want %d", len(out), n)
		}
		for i := range out {
			if out[i] != in[i] {
				t.Fatalf("topic %d differs", i)
			}
		}
	}
}

func TestFormat(t *testing.T) {
	b, err := Encode([][32]byte{topic(7)})
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0, 1}, raw(7)...)
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = %x, want %x", b, want)
	}
	if len(maxHello(t)) != MaxHelloSize {
		t.Fatalf("largest hello is %d bytes, MaxHelloSize %d", len(maxHello(t)), MaxHelloSize)
	}
	r, err := EncodeReply(0x0102030405060708, 300, [][32]byte{topic(7)})
	if err != nil {
		t.Fatal(err)
	}
	want = append([]byte{0, 8, 7, 6, 5, 4, 3, 2, 1, 0xac, 0x02, 1}, raw(7)...)
	if !bytes.Equal(r, want) {
		t.Fatalf("EncodeReply = %x, want %x", r, want)
	}
	if len(maxReply(t)) != MaxSize {
		t.Fatalf("largest reply is %d bytes, MaxSize %d", len(maxReply(t)), MaxSize)
	}
}

func TestEncodeRejects(t *testing.T) {
	many := make([][32]byte, MaxTopics+1)
	for i := range many {
		many[i] = topic(byte(i))
	}
	if _, err := Encode(many); !errors.Is(err, ErrInvalid) {
		t.Fatalf("too many topics: %v", err)
	}
	if _, err := Encode([][32]byte{topic(1), topic(1)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate topic: %v", err)
	}
}

func TestDecodeRejects(t *testing.T) {
	one := append([]byte{0, 1}, raw(1)...)
	dup := append(append([]byte{0, 2}, raw(1)...), raw(1)...)
	over := []byte{0, MaxTopics + 1}
	for i := 0; i <= MaxTopics; i++ {
		x := topic(byte(i))
		over = append(over, x[:]...)
	}
	tests := map[string][]byte{
		"empty":           nil,
		"version 1":       append([]byte{1, 1}, raw(1)...),
		"non-minimal":     append([]byte{0x80, 0x00, 1}, raw(1)...),
		"short topic":     one[:len(one)-1],
		"missing count":   {0},
		"trailing":        append(bytes.Clone(one), 0),
		"duplicate":       dup,
		"too many topics": over,
		"oversize":        make([]byte, MaxSize+1),
	}
	for name, b := range tests {
		if _, err := Decode(b); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestErrorIsFixed(t *testing.T) {
	_, err := Decode([]byte{0, 0x7f})
	if err != ErrInvalid {
		t.Fatalf("err = %v, want the bare sentinel", err)
	}
}

// maxHello returns the largest valid hello.
func maxHello(tb testing.TB) []byte {
	tb.Helper()
	var all [][32]byte
	for i := range MaxTopics {
		all = append(all, topic(byte(i)))
	}
	b, err := Encode(all)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func raw(b byte) []byte {
	t := topic(b)
	return t[:]
}

// maxReply returns the largest valid reply.
func maxReply(tb testing.TB) []byte {
	tb.Helper()
	var all [][32]byte
	for i := range MaxTopics {
		all = append(all, topic(byte(i)))
	}
	b, err := EncodeReply(^uint64(0), ^uint64(0), all)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func TestReplyRoundTrip(t *testing.T) {
	for _, gen := range []uint64{0, 1, 1 << 40, ^uint64(0)} {
		for _, n := range []int{1, 2, MaxTopics} {
			var in [][32]byte
			for i := range n {
				in = append(in, topic(byte(i)))
			}
			b, err := EncodeReply(gen^0x5a5a, gen, in)
			if err != nil {
				t.Fatal(err)
			}
			e, g, out, err := DecodeReply(b)
			if err != nil || e != gen^0x5a5a || g != gen || len(out) != n {
				t.Fatalf("gen %d, %d topics: got epoch %d, gen %d, %d topics, %v", gen, n, e, g, len(out), err)
			}
			for i := range out {
				if out[i] != in[i] {
					t.Fatalf("topic %d differs", i)
				}
			}
		}
	}
}

func TestReplyRejects(t *testing.T) {
	if _, err := EncodeReply(1, 1, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reply with no topic: %v", err)
	}
	one, _ := EncodeReply(9, 5, [][32]byte{topic(1)})
	epoch := []byte{0, 9, 0, 0, 0, 0, 0, 0, 0}
	with := func(rest ...byte) []byte { return append(bytes.Clone(epoch), rest...) }
	tests := map[string][]byte{
		"empty":             nil,
		"no topic":          with(5, 0),
		"version 1":         append([]byte{1}, one[1:]...),
		"short epoch":       {0, 9, 0, 0},
		"non-minimal gen":   append(with(0x85, 0x00, 1), raw(1)...),
		"gen overflow":      append(with(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 1), raw(1)...),
		"short topic":       one[:len(one)-1],
		"trailing":          append(bytes.Clone(one), 0),
		"duplicate":         append(append(with(5, 2), raw(1)...), raw(1)...),
		"oversize":          make([]byte, MaxSize+1),
		"hello is no reply": append([]byte{0, 1}, raw(1)...),
	}
	for name, b := range tests {
		if _, _, _, err := DecodeReply(b); err != ErrInvalid {
			t.Errorf("%s: err = %v, want the bare ErrInvalid", name, err)
		}
	}
}
