package koloswarm

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidConfig means a Config field is out of range, here or in kolo-dht (whose error is wrapped).
	ErrInvalidConfig = errors.New("koloswarm: invalid config")
	// ErrInvalidArgument means a nil identity or Conn, an IPv6 address (kolo-swarm is IPv4 only), invalid JoinOptions, a
	// topic already joined, a MaxTopics the application set reached, or a Connect key, topic or address that cannot be used.
	ErrInvalidArgument = errors.New("koloswarm: invalid argument")
	// ErrClosed means the swarm is closed.
	ErrClosed = errors.New("koloswarm: closed")
	// ErrRefused means a connection was refused by Allow, a limit, the lack of a shared topic, or the peer; for
	// Connect also the key's, host's or address's backoff, the dial rate, or Leave of the topic.
	ErrRefused = errors.New("koloswarm: connection refused")
	// ErrWait wraps ErrRefused: Connect was refused for now by a backoff (of the key, the address, the key at the
	// address, or the host), the dial rate, a dial to the host in progress, or MaxConnecting dials running.
	ErrWait = fmt.Errorf("%w: wait", ErrRefused)
	// ErrDuplicate means the pair of keys already has a connection that this one does not replace, or, for Connect, a
	// lookup dial, a proved dial or a hello of the key, or a Connect dial of it at the same address.
	ErrDuplicate = errors.New("koloswarm: duplicate connection")
	// ErrProtocol means the peer sent a malformed hello, or none in time.
	ErrProtocol = errors.New("koloswarm: protocol error")
	// ErrLost means a connection ended for another reason: the peer closed it, or it timed out or failed; or a Connect
	// dial failed.
	ErrLost = errors.New("koloswarm: connection lost")
)
