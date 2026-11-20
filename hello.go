package koloswarm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/ciranda-dev/kolo-swarm/internal/hello"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// handshake runs the hello on c and admits it, closing c on any error. The smaller key arbitrates and replies only on
// the connection it keeps; each side has a quickHello window per step.
func (s *Swarm) handshake(ctx context.Context, c Conn, k key, inbound, direct bool) error {
	return s.handshakeFor(ctx, c, k, inbound, direct, nil, nil)
}

// handshakeFor is handshake for a connection Connect dialed into the place res, claiming its topics, or for any other
// when res is nil.
func (s *Swarm) handshakeFor(ctx context.Context, c Conn, k key, inbound, direct bool, res *slot, claim []Topic) error {
	addr := remoteAddr(c)
	if !s.allow(k[:], addr) {
		return refuse(c, codeRefused, ErrRefused)
	}
	hctx, cancel := context.WithTimeout(ctx, s.cfg.HelloTimeout)
	defer cancel()
	cstop := context.AfterFunc(c.Context(), cancel)
	defer cstop()
	quick := quickHello
	if q := s.hooks.quick.Load(); q > 0 {
		quick = time.Duration(q)
	}
	quick = min(quick, s.cfg.HelloTimeout)

	if bytes.Compare(s.key, k[:]) < 0 {
		window := time.AfterFunc(quick, cancel)
		defer window.Stop()
		st, err := c.AcceptStream(hctx)
		if err != nil {
			return s.failed(ctx, c, err)
		}
		dstop := context.AfterFunc(hctx, func() { st.SetDeadline(time.Now()) })
		defer dstop()
		b, err := readMsg(st)
		if err != nil {
			return s.failed(ctx, c, err)
		}
		if s.hooks.afterHello != nil {
			s.hooks.afterHello()
		}
		if !window.Stop() {
			return refuse(c, codeProtocol, ErrProtocol)
		}
		raw, err := hello.Decode(b)
		if err != nil {
			st.CancelRead(codeProtocol)
			return refuse(c, codeProtocol, ErrProtocol)
		}
		s.mu.Lock()
		shared := s.foundTopicsLocked(k, claim...)
		for _, x := range raw {
			if !slices.Contains(shared, Topic(x)) && len(shared) < hello.MaxTopics {
				shared = append(shared, Topic(x))
			}
		}
		s.mu.Unlock()
		p, code, err := s.admitFor(c, k, addr, inbound, direct, shared, false, generation{}, res)
		if err != nil {
			return refuse(c, code, err)
		}
		// No window: the QUIC stack queues a write this small without flow-control credit, and a failed reply only leaves
		// the other side to time out.
		if s.hooks.beforeReply != nil {
			s.hooks.beforeReply()
		}
		if msg, err := hello.EncodeReply(p.gen.epoch, p.gen.n, rawTopics(p.topics)); err == nil {
			st.Write(msg)
		}
		st.Close()
		return nil
	}

	s.mu.Lock()
	mine := s.foundTopicsLocked(k, claim...)
	s.mu.Unlock()
	msg, err := hello.Encode(rawTopics(mine))
	if err != nil {
		return refuse(c, codeProtocol, ErrProtocol)
	}
	// The peer controls the stream limit and flow control, so opening and sending get a window too.
	send := time.AfterFunc(quick, cancel)
	defer send.Stop()
	st, err := c.OpenStream(hctx)
	if err != nil {
		return s.failed(ctx, c, err)
	}
	dstop := context.AfterFunc(hctx, func() { st.SetDeadline(time.Now()) })
	defer dstop()
	if _, err := st.Write(msg); err != nil {
		return s.failed(ctx, c, err)
	}
	st.Close()
	if !send.Stop() {
		return refuse(c, codeProtocol, ErrProtocol)
	}
	window := time.AfterFunc(quick, cancel)
	defer window.Stop()
	b, err := readMsg(st)
	if err != nil {
		return s.failed(ctx, c, err)
	}
	if s.hooks.afterHello != nil {
		s.hooks.afterHello()
	}
	if !window.Stop() {
		return refuse(c, codeProtocol, ErrProtocol)
	}
	epoch, n, raw, err := hello.DecodeReply(b)
	if err != nil {
		st.CancelRead(codeProtocol)
		return refuse(c, codeProtocol, ErrProtocol)
	}
	shared := make([]Topic, len(raw))
	for i, x := range raw {
		shared[i] = Topic(x)
	}
	if _, code, err := s.admitFor(c, k, addr, inbound, direct, shared, true, generation{epoch, n}, res); err != nil {
		return refuse(c, code, err)
	}
	return nil
}

// readMsg reads the whole stream, up to one byte over hello.MaxSize so the decoder rejects more.
func readMsg(st *kolotransport.Stream) ([]byte, error) {
	return io.ReadAll(io.LimitReader(st, hello.MaxSize+1))
}

func rawTopics(topics []Topic) [][32]byte {
	raw := make([][32]byte, len(topics))
	for i, t := range topics {
		raw[i] = t
	}
	return raw
}

func refuse(c Conn, code uint64, err error) error {
	c.CloseWithError(code, "")
	return err
}

// failed closes c after a hello error and maps the error to a sentinel.
func (s *Swarm) failed(ctx context.Context, c Conn, err error) error {
	if code, ok := peerCode(err); ok || c.Context().Err() != nil {
		if !ok {
			code, ok = peerCode(context.Cause(c.Context()))
		}
		c.CloseWithError(codeNormal, "")
		if ok {
			switch code {
			case codeDuplicate:
				return ErrDuplicate
			case codeFull, codeRefused:
				return ErrRefused
			}
		}
		return ErrProtocol
	}
	switch {
	case s.ctx.Err() != nil:
		c.CloseWithError(codeNormal, "")
		return ErrClosed
	case ctx.Err() != nil:
		c.CloseWithError(codeNormal, "")
		return ctx.Err()
	}
	return refuse(c, codeProtocol, ErrProtocol)
}

// peerCode returns the code the peer closed the connection with, if err says it did.
func peerCode(err error) (uint64, bool) {
	var te *kolotransport.Error
	if errors.As(err, &te) && errors.Is(te.Err, kolotransport.ErrPeerClosed) {
		return te.Code, true
	}
	return 0, false
}

// lostErr maps the cause of a lost connection to a sentinel, so Event.Err carries nothing the peer sent.
func lostErr(cause error) error {
	var te *kolotransport.Error
	if !errors.As(cause, &te) {
		return ErrLost
	}
	local, peer := errors.Is(te.Err, kolotransport.ErrClosed), errors.Is(te.Err, kolotransport.ErrPeerClosed)
	switch {
	case !local && !peer:
		return ErrLost
	case te.Code == codeDuplicate:
		return ErrDuplicate
	case local:
		return ErrClosed
	case te.Code == codeFull || te.Code == codeRefused:
		return ErrRefused
	case te.Code == codeProtocol:
		return ErrProtocol
	}
	return ErrLost
}
