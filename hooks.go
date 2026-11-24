package koloswarm

import (
	"context"
	"crypto/ed25519"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolorelay "github.com/ciranda-dev/kolo-relay"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

// testHooks are set only by tests, after New and before the swarm has work for them; a nil hook does nothing.
type testHooks struct {
	afterHello    func()                                // runs after a hello or reply is read, before its window is checked
	afterLookup   func()                                // runs after each lookup of a topic
	beforeReply   func()                                // runs after the arbiter admits, before it writes the reply
	addrsOf       func(kolodht.Record) []netip.AddrPort // replaces Record.Addrs, whose relays tests cannot set
	rng           *rand.Rand                            // replaces math/rand/v2 for candidate sampling
	quick         atomic.Int64                          // replaces quickHello when above zero
	grow          func(Conn)                            // runs before the swarm marks a connection for window growth
	beforeCleanup func()                                // runs when a Connect call starts its cleanup

	announce    func(context.Context, kolodht.Topic) error                                         // replaces node.Announce
	connect     func(context.Context, kolodht.Record) (*kolosecure.Conn, error)                    // replaces node.Connect
	dial        func(context.Context, netip.AddrPort, ed25519.PublicKey) (*kolosecure.Conn, error) // replaces Connect's kolosecure.Dial
	accept      func(context.Context, *kolorelay.Reservation) (Conn, error)                        // replaces Reservation.Accept
	beforeRelay func(ctx context.Context, relay, target ed25519.PublicKey)                         // runs before each relay dial
	relayAfter  time.Duration                                                                      // replaces the punch window when above zero
}

// nodeHooks are set only by tests, which restore them afterwards.
var nodeHooks = struct {
	lookupIP       resolver          // resolves bootstrap and relay names
	resolveTimeout time.Duration     // bounds the resolution of each name
	fileChecked    func(path string) // runs once a node file passed its path check
	fileOpened     func(path string) // runs once a node file is open
}{lookupIP: net.DefaultResolver, resolveTimeout: 5 * time.Second}
