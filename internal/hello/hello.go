// Package hello encodes the two messages that start a kolo-swarm connection: the hello and the arbiter's reply.
package hello

import (
	"errors"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

const (
	// Version is the only message version.
	Version = 0
	// MaxTopics is the most topics one message carries.
	MaxTopics = 32
	// MaxHelloSize is the largest hello in bytes: version, count and MaxTopics topics.
	MaxHelloSize = 2 + MaxTopics*32
	// MaxSize is the largest message in bytes, a reply with its 8-byte epoch and a 10-byte generation.
	MaxSize = MaxHelloSize + 8 + 10
)

// ErrInvalid means a message is malformed, of another version, too large, or lists a topic twice.
var ErrInvalid = errors.New("koloswarm: invalid hello")

// Encode returns the hello for topics, which must be distinct and at most MaxTopics.
func Encode(topics [][32]byte) ([]byte, error) {
	if len(topics) > MaxTopics || hasDup(topics) {
		return nil, ErrInvalid
	}
	var e kolocodec.Encoder
	e.PutUvarint(Version)
	putTopics(&e, topics)
	return e.Bytes(), nil
}

// EncodeReply returns the reply for the arbiter's epoch, generation gen and topics, which must be 1 to MaxTopics
// distinct topics.
func EncodeReply(epoch, gen uint64, topics [][32]byte) ([]byte, error) {
	if len(topics) == 0 || len(topics) > MaxTopics || hasDup(topics) {
		return nil, ErrInvalid
	}
	var e kolocodec.Encoder
	e.PutUvarint(Version)
	e.PutUint64(epoch)
	e.PutUvarint(gen)
	putTopics(&e, topics)
	return e.Bytes(), nil
}

func putTopics(e *kolocodec.Encoder, topics [][32]byte) {
	e.PutUvarint(uint64(len(topics)))
	for _, t := range topics {
		e.PutFixed(t[:])
	}
}

// Decode parses a hello; every error is ErrInvalid itself, so it carries nothing from b.
func Decode(b []byte) ([][32]byte, error) {
	if len(b) > MaxHelloSize {
		return nil, ErrInvalid
	}
	d := kolocodec.NewDecoder(b)
	if v, err := d.Uvarint(); err != nil || v != Version {
		return nil, ErrInvalid
	}
	return topicsOf(d)
}

// DecodeReply parses a reply into its epoch, generation and topics; every error is ErrInvalid itself.
func DecodeReply(b []byte) (epoch, gen uint64, topics [][32]byte, err error) {
	if len(b) > MaxSize {
		return 0, 0, nil, ErrInvalid
	}
	d := kolocodec.NewDecoder(b)
	if v, err := d.Uvarint(); err != nil || v != Version {
		return 0, 0, nil, ErrInvalid
	}
	if epoch, err = d.Uint64(); err != nil {
		return 0, 0, nil, ErrInvalid
	}
	if gen, err = d.Uvarint(); err != nil {
		return 0, 0, nil, ErrInvalid
	}
	topics, err = topicsOf(d)
	if err != nil || len(topics) == 0 {
		return 0, 0, nil, ErrInvalid
	}
	return epoch, gen, topics, nil
}

func topicsOf(d *kolocodec.Decoder) ([][32]byte, error) {
	n, err := d.UvarintMax(MaxTopics)
	if err != nil {
		return nil, ErrInvalid
	}
	topics := make([][32]byte, 0, n)
	for range n {
		t, err := d.Fixed(32)
		if err != nil {
			return nil, ErrInvalid
		}
		topics = append(topics, [32]byte(t))
	}
	if d.Done() != nil || hasDup(topics) {
		return nil, ErrInvalid
	}
	return topics, nil
}

func hasDup(topics [][32]byte) bool {
	seen := make(map[[32]byte]bool, len(topics))
	for _, t := range topics {
		if seen[t] {
			return true
		}
		seen[t] = true
	}
	return false
}
