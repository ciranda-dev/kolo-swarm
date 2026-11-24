package koloswarm

import (
	"cmp"
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// Config sets the limits of a Swarm. A zero field takes its default; out of range is ErrInvalidConfig.
type Config struct {
	// DHT is passed to kolodht.New. A zero MaxAnnouncements becomes MaxTopics, a lower one is refused, and zero
	// kolo-transport MaxDialed, MaxConns and MaxMemory are raised to cover MaxPeers, and MaxMemory also the growth
	// WindowGrowth allows. With Allow set, WindowGrowth lets the connections Allow admitted grow their windows.
	DHT *kolodht.Config
	// MaxPeers caps connected peers plus dials in progress, inbound and outbound. Default 64, from 1 to 1024.
	MaxPeers int
	// MaxInbound caps the peers that connected to us. Default MaxPeers/2 rounded up, from 1 to MaxPeers.
	MaxInbound int
	// MaxConnectPeers caps the places Swarm.Connect holds. Default MaxPeers/4, from 1 to MaxPeers - MaxInbound; when
	// MaxInbound equals MaxPeers it must be unset, and Connect is always refused.
	MaxConnectPeers int
	// MaxTopics caps the topics joined at once. Default 16, from 1 to 32.
	MaxTopics int
	// MaxConnecting caps kolo-dht Connect calls in progress, and separately relay dials and Swarm.Connect dials, and
	// is also the Swarm.Connect dial starts per RetryMin. Default 3, from 1 to 16.
	MaxConnecting int
	// MaxHandshakes caps hellos in progress. From 4 up, a quarter is kept for Attach and another for known keys (an
	// outbound slot, or an outbound connection that lasted 15s). Default 16, from 1 to 256.
	MaxHandshakes int
	// MaxHandshakesPerIP caps hellos in progress from one source host, or through one relay. Default 4 (or
	// MaxHandshakes if lower), from 1 to MaxHandshakes.
	MaxHandshakesPerIP int
	// MaxCandidates caps the keys kept from lookups, split equally between joined topics; the backoff of up to twice
	// as many dropped keys, and keys Swarm.Connect dialed, is kept. Default 1024, from 16 to 32768.
	MaxCandidates int
	// MaxEvents caps the queued Found events, and separately the queued Unreachable events; more are dropped.
	// Default 64, from 16 to 4096.
	MaxEvents int
	// HelloTimeout bounds the hello on a new connection. Default 10s, from 1s to 60s.
	HelloTimeout time.Duration
	// LookupInterval is the time between lookups of a topic, plus up to a fifth of it at random. Default 10m, from
	// 1s to 1h.
	LookupInterval time.Duration
	// RetryMin is the shortest wait before dialing a key again, and the period in which Swarm.Connect starts at most
	// MaxConnecting dials, so raising it slows Connect. Default 1s, from 100ms to 1m.
	RetryMin time.Duration
	// RetryMax is the longest wait before dialing a key again. Default 10m, from RetryMin to 1h.
	RetryMax time.Duration
	// Allow, if set, is asked before every dial and every new connection; false or a panic refuses. addr is the
	// address to dial or the connection's remote address, zero when the Conn has none.
	Allow func(key ed25519.PublicKey, addr netip.AddrPort) bool
	// BootstrapNodes are the entry nodes Bootstrap uses when it is given none: at most 16 host:port entries, each an
	// IPv4 address or a host name resolved to IPv4, as from ParseNodes or LoadNodes. The default is empty, and Bootstrap
	// then falls back to kolo-dht's public entry nodes, which then receive this node's IP address and public key; set
	// it to stay off the public network.
	BootstrapNodes []string
	// Relays, if not empty, connect peers that cannot connect directly: at most 16, in order of preference. While a
	// topic is joined with Announce the swarm keeps a reservation at each and admits the peers that come through
	// them, and a key whose kolo-dht Connect failed, or ran past the punch window of two consistent mappings (12s at
	// the defaults), is dialed through them in turn, the one that carried it last first, with the swarm's own
	// DHT.Secure settings. Two peers meet through any relay both list. Empty never uses a relay.
	Relays []Relay
}

// Relay is a kolo-relay that peers of the network may list, used when a direct connection fails.
type Relay struct {
	// Addr is the relay's host:port, an IPv4 address or a host name resolved to IPv4, in the form of a
	// BootstrapNodes entry. A name must point to one relay process.
	Addr string
	// PublicKey is the relay's kolo-id public key.
	PublicKey ed25519.PublicKey
}

// The defaults of kolo-secure MaxPending and kolo-transport MaxDialed and MaxConns, which the swarm only raises.
const (
	securePending   = 64
	transportDialed = 32
	transportConns  = 100
)

func bound[T int | time.Duration](name string, v *T, def, lo, hi T) error {
	switch {
	case *v == 0:
		*v = def
	case *v < lo || *v > hi:
		return fmt.Errorf("%w: %s must be between %v and %v", ErrInvalidConfig, name, lo, hi)
	}
	return nil
}

func (c *Config) withDefaults() (Config, error) {
	var out Config
	if c != nil {
		out = *c
	}
	if err := bound("MaxPeers", &out.MaxPeers, 64, 1, 1024); err != nil {
		return Config{}, err
	}
	if err := bound("MaxTopics", &out.MaxTopics, 16, 1, 32); err != nil {
		return Config{}, err
	}
	if err := bound("MaxConnecting", &out.MaxConnecting, 3, 1, 16); err != nil {
		return Config{}, err
	}
	if err := bound("MaxHandshakes", &out.MaxHandshakes, 16, 1, 256); err != nil {
		return Config{}, err
	}
	if err := bound("MaxCandidates", &out.MaxCandidates, 1024, 16, 32768); err != nil {
		return Config{}, err
	}
	if err := bound("MaxEvents", &out.MaxEvents, 64, 16, 4096); err != nil {
		return Config{}, err
	}
	if err := bound("MaxInbound", &out.MaxInbound, (out.MaxPeers+1)/2, 1, out.MaxPeers); err != nil {
		return Config{}, err
	}
	room := out.MaxPeers - out.MaxInbound
	switch {
	case out.MaxConnectPeers == 0:
		out.MaxConnectPeers = min(max(1, out.MaxPeers/4), room)
	case room == 0:
		return Config{}, fmt.Errorf("%w: MaxConnectPeers must be unset when MaxInbound equals MaxPeers, which refuses every Connect", ErrInvalidConfig)
	case out.MaxConnectPeers < 1 || out.MaxConnectPeers > room:
		return Config{}, fmt.Errorf("%w: MaxConnectPeers must be between 1 and %d (MaxPeers - MaxInbound)", ErrInvalidConfig, room)
	}
	if err := bound("MaxHandshakesPerIP", &out.MaxHandshakesPerIP, min(4, out.MaxHandshakes), 1, out.MaxHandshakes); err != nil {
		return Config{}, err
	}
	if err := bound("HelloTimeout", &out.HelloTimeout, 10*time.Second, time.Second, time.Minute); err != nil {
		return Config{}, err
	}
	if err := bound("LookupInterval", &out.LookupInterval, 10*time.Minute, time.Second, time.Hour); err != nil {
		return Config{}, err
	}
	if err := bound("RetryMin", &out.RetryMin, time.Second, 100*time.Millisecond, time.Minute); err != nil {
		return Config{}, err
	}
	if err := bound("RetryMax", &out.RetryMax, 10*time.Minute, out.RetryMin, time.Hour); err != nil {
		return Config{}, err
	}
	nodes, err := checkNodes(out.BootstrapNodes)
	if err != nil {
		return Config{}, fmt.Errorf("%w: BootstrapNodes: %w", ErrInvalidConfig, err)
	}
	out.BootstrapNodes = nodes
	relays, err := checkRelays(out.Relays)
	if err != nil {
		return Config{}, fmt.Errorf("%w: Relays: %w", ErrInvalidConfig, err)
	}
	out.Relays = relays
	var dht kolodht.Config
	if out.DHT != nil {
		dht = *out.DHT
	}
	switch {
	case dht.MaxAnnouncements == 0:
		dht.MaxAnnouncements = out.MaxTopics
	case dht.MaxAnnouncements < out.MaxTopics:
		return Config{}, fmt.Errorf("%w: DHT.MaxAnnouncements must be at least MaxTopics", ErrInvalidConfig)
	}
	var sec kolosecure.Config
	if dht.Secure != nil {
		sec = *dht.Secure
	}
	var tc kolotransport.Config
	if sec.Transport != nil {
		tc = *sec.Transport
	}
	pending := sec.MaxPending
	if pending == 0 {
		pending = securePending
	}
	if tc.MaxDialed == 0 {
		tc.MaxDialed = max(transportDialed, out.MaxPeers+out.MaxHandshakes+pending)
	}
	if tc.MaxConns == 0 {
		tc.MaxConns = max(transportConns, out.MaxInbound+out.MaxHandshakes+pending)
	}
	if tc.MaxMemory == 0 {
		win := tc.MaxConnReceiveWindow
		if win == 0 {
			win = kolotransport.DefaultMaxConnReceiveWindow
		}
		need := int64(tc.MaxConns+tc.MaxDialed) * win
		if tc.WindowGrowth {
			// An upper bound of the growth kolo-transport adds to its MaxMemory check.
			need += cmp.Or(tc.MaxGrownMemory, kolotransport.DefaultMaxGrownMemory)
		}
		tc.MaxMemory = max(kolotransport.DefaultMaxMemory, need)
	}
	sec.Transport = &tc
	dht.Secure = &sec
	out.DHT = &dht
	return out, nil
}
