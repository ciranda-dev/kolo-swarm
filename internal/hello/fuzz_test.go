package hello

import (
	"bytes"
	"testing"
)

func FuzzDecode(f *testing.F) {
	one, _ := Encode([][32]byte{topic(1)})
	two, _ := Encode([][32]byte{topic(1), topic(2)})
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Add(one)
	f.Add(two)
	f.Add(maxHello(f))
	f.Fuzz(func(t *testing.T, b []byte) {
		topics, err := Decode(b)
		if err != nil {
			if err != ErrInvalid {
				t.Fatalf("error %v is not the sentinel", err)
			}
			return
		}
		if len(b) > MaxHelloSize || len(topics) > MaxTopics {
			t.Fatalf("accepted %d bytes with %d topics", len(b), len(topics))
		}
		again, err := Encode(topics)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("not canonical: %x re-encodes as %x", b, again)
		}
	})
}

func FuzzDecodeReply(f *testing.F) {
	one, _ := EncodeReply(7, 1, [][32]byte{topic(1)})
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0})
	f.Add(one)
	f.Add(maxReply(f))
	f.Fuzz(func(t *testing.T, b []byte) {
		epoch, gen, topics, err := DecodeReply(b)
		if err != nil {
			if err != ErrInvalid {
				t.Fatalf("error %v is not the sentinel", err)
			}
			return
		}
		if len(b) > MaxSize || len(topics) == 0 || len(topics) > MaxTopics {
			t.Fatalf("accepted %d bytes with %d topics", len(b), len(topics))
		}
		again, err := EncodeReply(epoch, gen, topics)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("not canonical: %x re-encodes as %x, %v", b, again, err)
		}
	})
}
