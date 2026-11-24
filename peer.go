package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// Topic is a 32-byte topic, the same type as kolo-dht's.
type Topic = kolodht.Topic

// Conn is an authenticated connection to one peer; *kolosecure.Conn and *kolorelay.Conn both satisfy it.
// RemotePublicKey must be a key the connection has proved, as those two do; the swarm trusts it without a check.
type Conn interface {
	RemotePublicKey() ed25519.PublicKey
	OpenStream(ctx context.Context) (*kolotransport.Stream, error)
	AcceptStream(ctx context.Context) (*kolotransport.Stream, error)
	OpenUniStream(ctx context.Context) (*kolotransport.SendStream, error)
	AcceptUniStream(ctx context.Context) (*kolotransport.ReceiveStream, error)
	Context() context.Context
	Close() error
	CloseWithError(code uint64, msg string) error
}

// Peer is a connected peer: one connection to one remote key.
type Peer struct {
	s        *Swarm
	key      ed25519.PublicKey
	addr     netip.AddrPort
	conn     Conn
	direct   bool
	inbound  bool
	admitted time.Time
	gen      generation

	// Guarded by s.mu.
	topics    []Topic
	delivered bool
	gone      bool
}

// PublicKey returns a copy of the peer's kolo-id public key.
func (p *Peer) PublicKey() ed25519.PublicKey { return bytes.Clone(p.key) }

// Addr returns the peer's UDP address, or the zero AddrPort if its Conn has no RemoteAddr method.
func (p *Peer) Addr() netip.AddrPort { return p.addr }

// Conn returns the connection; the peer is lost when its Context ends.
func (p *Peer) Conn() Conn { return p.conn }

// Direct reports whether the connection is direct, from kolo-dht or Connect, rather than through one of Config.Relays
// or from Attach.
func (p *Peer) Direct() bool { return p.direct }

// Outbound reports whether the peer holds one of our outbound places (not capped by MaxInbound), whichever side opened
// the kept connection.
func (p *Peer) Outbound() bool { return !p.inbound }

// Topics returns the topics this peer currently shares with us, as far as the peer claimed them or our lookups found
// it on, more than the 32 a hello carries if need be: a topic hash is not secret, so any peer can claim it. Config.Allow, which sees the key, is where to admit only known members.
func (p *Peer) Topics() []Topic {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	return append([]Topic(nil), p.topics...)
}

// EventKind says what an Event reports.
type EventKind int

// The event kinds.
const (
	// Found means a lookup of Topic returned PublicKey at Addr, for the first time since it was last absent.
	Found EventKind = iota + 1
	// Connected means Peer is connected; its Conn is ready for streams.
	Connected
	// Unreachable means kolo-dht could not connect to PublicKey, found on Topic; Err is kolodht.ErrUnreachable. With
	// Config.Relays set, it comes only after the relays failed too.
	Unreachable
	// Lost means the connection of a Peer returned by an earlier Connected ended. Err says why, with nothing the peer
	// chose: ErrDuplicate (replaced, or closed as a duplicate), ErrClosed (closed here), ErrRefused or ErrProtocol (the
	// peer refused it), or ErrLost (anything else).
	Lost
	// RelayChanged means the reservation at the relay whose key is PublicKey is held (Err nil) or not held; Err is
	// then kolorelay.ErrNotAllowed, kolorelay.ErrLimit, kolorelay.ErrReservationEnded, kolosecure.ErrUnexpectedPeer,
	// ErrInvalidConfig (that relay's key cannot be used; the swarm stops using it), ErrClosed (no announced topic is
	// joined) or ErrLost (anything else). Topic, Addr and Peer are zero. Only the newest one per relay waits in the
	// queue.
	RelayChanged
)

// String returns the kind's name.
func (k EventKind) String() string {
	switch k {
	case Found:
		return "found"
	case Connected:
		return "connected"
	case Unreachable:
		return "unreachable"
	case Lost:
		return "lost"
	case RelayChanged:
		return "relay changed"
	}
	return "unknown"
}

// Event is one thing that happened in the swarm; which fields are set depends on Kind.
type Event struct {
	Kind      EventKind
	Topic     Topic             // set for Found and Unreachable
	PublicKey ed25519.PublicKey // the remote key, or the relay's key for RelayChanged
	Addr      netip.AddrPort    // the remote address; zero for RelayChanged
	Peer      *Peer             // set for Connected and Lost
	Err       error             // set for Unreachable and Lost, and for RelayChanged when the reservation is not held
}

// remoteAddr returns the remote UDP address of c, unmapped since the OS may report IPv4 in 16 bytes, or zero.
func remoteAddr(c Conn) netip.AddrPort {
	ra, ok := c.(interface{ RemoteAddr() net.Addr })
	if !ok {
		return netip.AddrPort{}
	}
	ua, ok := ra.RemoteAddr().(*net.UDPAddr)
	if !ok || ua == nil {
		return netip.AddrPort{}
	}
	ap := ua.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
