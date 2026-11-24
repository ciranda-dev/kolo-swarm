# Guide

How to use kolo-swarm beyond the README quick start. Every default and bound is in [limits.md](limits.md); the design, the wire format and references are in [protocol.md](protocol.md).

A real deployment bootstraps from a few kolo-dht servers, such as kolo-node; see [Public and private networks](#public-and-private-networks). Peers that cannot connect directly can meet through kolo-relays; see [Relay fallback](#relay-fallback).

## API

- `New(ctx, addr, id, cfg) (*Swarm, error)` opens a kolo-dht node on
  `addr` (such as `"127.0.0.1:0"` or `":4000"`) as `id` and starts the
  swarm. `Addr()` and `PublicKey()` are the node's. `Bootstrap(ctx,
  servers)` is kolo-dht's: its `ErrNoNodes` passes through, and its
  `ErrInvalidArgument` is wrapped in ours, so both sentinels match. With
  no `servers` it uses `Config.BootstrapNodes` instead; with neither, a nil
  list joins the public network (see
  [Public and private networks](#public-and-private-networks)) and an empty
  list that is not nil is `ErrInvalidArgument`.
- `ParseNodes(s)` parses a comma-separated list of bootstrap nodes, each
  `host:port` with an IPv4 address or a host name, for
  `Config.BootstrapNodes`. Spaces and empty entries are ignored and
  duplicates dropped; a bad entry, an IPv6 address in any form or port 0
  is `ErrInvalidArgument`, naming the entry's position. The list has no
  length limit. `Config.BootstrapNodes` takes one entry per element: an
  element with a comma is refused (`want host:port`), and so is one with
  spaces.
- `LoadNodes(path)` reads the same list from a file, one `host:port` per
  line; `#` starts a comment, blank lines are ignored, and a UTF-8 BOM and
  CRLF line ends are accepted. It reads only a regular file of at most
  64 KiB: a directory, device or FIFO is refused before it is opened. A bad
  line is `ErrInvalidArgument` naming its line number, never its content;
  a file that cannot be read gives the `os` error, which names the path.
- `Join(ctx, topic, opts)` joins a 32-byte topic. Nil `opts` means
  `Announce` and `Lookup`; a non-nil `JoinOptions` needs at least one.
  With `Announce`, it returns once kolo-dht stored our record, and
  kolo-dht's errors (`ErrNotStored`, `ErrNoNodes`) pass through; the topic
  is then not joined. First announcements are paced, at most 10 a second
  after a burst of 10, so a swarm that joins many topics at once stays
  within the 20 checked announcements a second kolo-dht allows each
  address, and `ErrNotStored` is retried 3 times, after 1s to 8s of
  jittered backoff, before it passes through; a `Join` can so take up to
  about 14s longer. With `Lookup`, a lookup runs at once, then every
  `LookupInterval` plus up to a fifth of it at random, skipped while the
  topic is at its limit. There is no limit on the topics joined unless the
  application sets `MaxTopics`. `JoinOptions.MaxPeers` caps the peers
  dialed or admitted for the topic; left at zero the topic may use any free
  place, and when places run out it is kept a fair share of `MaxPeers`: the
  swarm closes a peer of a topic above its share, or an inbound peer, to
  dial for a topic below its share or below 6 outbound peers (that peer's
  `Lost` carries `ErrClosed`, and the peer sees code 3). Inbound peers
  take at most the topic's inbound share (see [protocol.md](protocol.md)).
  A topic already joined, or a `MaxTopics` the application set reached, is
  `ErrInvalidArgument`. If `Leave(topic)` runs during `Join`, `Join`
  returns `context.Canceled`. With `Announce` and `Config.Relays`, `Join`
  first waits for the first reservation attempt at each listed relay, in
  parallel, at most about 40s, except relays known down; a failed attempt
  never fails `Join`.
- `Leave(topic)` stops announcing and looking up the topic and closes
  (code 0) the peers that share no other topic with us, as far as our own
  lookups know. It does not block.
  With `Config.Relays` set, those closes run in parallel and can finish
  after `Leave` returns (a relayed close takes about 2s when the other
  side is gone), so a closed peer's `Lost` may come later.
- `Next(ctx) (Event, error)` returns the next event:
  - `Found`: a lookup of `Topic` returned `PublicKey` at `Addr`, for the
    first time since it was last absent.
  - `Connected`: `Peer` is connected.
  - `Unreachable`: kolo-dht could not connect to `PublicKey`, found on
    `Topic`; `Err` is `kolodht.ErrUnreachable`. With `Config.Relays` set,
    it comes only after the relays failed too; a key whose `Connect` failed
    while `MaxConnecting` relay dials ran gets none and is retried as after
    try later. The swarm keeps retrying with backoff, and the application
    may try another path and `Attach` it.
  - `Lost`: the connection of a peer from an earlier `Connected` ended.
    `Err` is a bare sentinel with nothing the peer chose: `ErrDuplicate`
    (replaced by a newer connection to the same key, or closed by either
    side with code 2), `ErrClosed` (closed here with another code: `Close`,
    `Leave` or the application), `ErrRefused` (the peer closed it with code
    3 or 4), `ErrProtocol` (the peer closed it with code 5) or `ErrLost`
    (anything else: another code from the peer, an idle timeout, a QUIC or
    transport error). A replaced peer's `Lost` comes before the new
    `Connected`.
  - `RelayChanged`: the reservation at the listed relay whose key is
    `PublicKey` is held (`Err` nil) or not; see [Relay fallback](#relay-fallback).

  `Connected` and `Lost` are never dropped. At most `MaxEvents` `Found`
  wait, and separately at most `MaxEvents` `Unreachable`; newer ones are
  dropped. At most one `RelayChanged` per listed relay waits: a newer one
  replaces it. A peer lost before `Next` returned its `Connected` gives no
  event. So at most 2 × `MaxPeers` + 2 × `MaxEvents` + the number of
  listed relays events wait, and a
  slow reader never blocks the swarm. In a simultaneous open, each side
  may see `Connected`, `Lost`, `Connected` for one key.
- `Attach(ctx, conn, outbound)` hands the swarm a connection the
  application opened itself; both ends must attach it. It runs the hello,
  `Allow`, the limits and dedup like any connection, and returns nil once
  the peer is admitted. Its `Connected` follows with `Direct()` false. It
  never replaces a connection from kolo-dht (`ErrDuplicate`). With
  `Config.Relays` set, an attached connection counts as relayed: a direct
  dial to its key that is running goes on and replaces it if it connects
  (`Lost` with `ErrDuplicate`), and the key's next dial also runs through
  the relays at once. Other
  errors: `ErrRefused`, `ErrProtocol`, `ErrInvalidArgument` (nil `Conn`,
  a key that is not 32 bytes or is ours, an IPv6 remote address),
  `ctx.Err()` and `ErrClosed`. The swarm owns `conn` from the call on and
  closes it on any error. `Attach` blocks for up to `HelloTimeout`, so run
  it in its own goroutine. The hello has the same windows as on any
  connection: the end with the smaller key must receive the whole HELLO
  within 2s of its own call; the other end must open the stream and send
  its HELLO within 2s of its call, then receive the whole REPLY within 2s
  more. So both ends should call `Attach` as soon as the connection is up.
  The connection must authenticate `RemotePublicKey` itself, as
  kolo-secure does: the swarm trusts the key and the hello carries no
  proof, so a `Conn` that returns the key the peer claims lets any peer
  impersonate any key.
- `Connect(ctx, topic, key, addr, from)` dials one known key at one known
  IPv4 address directly with kolo-secure, from a UDP socket of its own, and
  runs the hello for `topic`, which must be joined; it suits addresses
  learned outside kolo-dht, such as from another peer. `from` is the
  address of the peer that supplied `addr`, and `addr` passes when it is
  global or in the scope of `from`: loopback for a loopback `from`,
  link-local for a link-local one, any of 10/8, 172.16/12 and 192.168/16
  for a `from` in one of them, and 100.64/10 (carrier-grade NAT) only for
  a `from` in 100.64/10. This is kolo-dht's rule for addresses learned
  from others, with carrier-grade NAT apart, so a remote peer cannot point
  the swarm into a local network. A zero `from` means an unknown source,
  and only a global `addr` passes. A relayed or attached peer has no
  address (`Peer.Addr()` is zero), so what it supplies must be global. An
  application that learned `addr` itself passes its own address, such as
  the IP of `Addr()`. `addr` must not be the swarm's own socket, or, when
  it listens on every address, a loopback or interface address at its
  port; a public address a NAT maps to the swarm is not known here, so a
  hairpin dial to it is refused only by the key check.
  Until kolo-secure proves the key, the dial holds a place in `MaxPeers`,
  `MaxConnectPeers` and the topic but no place of the key, so a dial of the
  same key at another address, from `Connect` or a lookup, goes on
  meanwhile. Once the key proved itself, the dial takes the key's place,
  reserved until `Connect` returns: a connection from the key that comes
  in during the hello may fill it, and one that is lost meanwhile leaves
  it to the `Connect`. If the key already has a place by then, the dial is
  dropped with `ErrDuplicate`, except that a direct dial replaces a
  relayed peer that arrived during the dial, as a lookup dial does;
  `Connect` never replaces a relayed connection that existed before the
  call (that is `ErrDuplicate` too). `Leave` stops a dial that has not
  proved its key; a hello already running ends within `HelloTimeout`, and
  the key is then admitted only for other topics it shares with us, if
  any.
  It returns nil only once this dial's connection is admitted; the peer
  comes through `Next` as `Connected`, with `Outbound()` true, or the
  direction of the relayed peer's place when it replaced one. As after
  any hello, the end with the larger key may still refuse it (no shared
  topic, full), which ends it with `Lost`. `ErrDuplicate` means the key
  already has a place (a peer, a lookup dial, or a `Connect` dial that
  proved it), a hello in progress, or a `Connect` dial at this same
  address; a `Connect` dial of the key at another address does not count.
  A caller that only wants the key connected can treat it as success.
  Bounds: those of a dial from a lookup (`Allow`, asked with `addr`;
  `MaxPeers`; the topic's `MaxPeers`; the key's own backoff; one dial in
  progress per host), plus its own: at most `MaxConnectPeers` places
  (dials not proved yet included, and an inbound connection that took
  one), at most `MaxConnecting` `Connect` dials at once (proved ones in
  their hello included), counted apart from kolo-dht's, and at most
  `MaxConnecting` dial starts per `RetryMin` (3 a second at the
  defaults). At an address lookups found for the key, the host rule is
  looser: another dial there that no lookup vouched for does not count,
  but only one such vouched dial runs per host, since a server can forge
  records.
  Backoff before the key proved itself: no answer or a timeout backs off
  that address (host and port) and the pair of key and address; another
  key answering backs off only the pair; the caller's deadline backs off
  the address. The address's backoff holds off only keys lookups did not
  find there, so a third party's dials to it never hold off the key
  lookups found there; that key is held only by its own pair and history.
  After the key proved itself, a failed hello or a lost
  connection charges the key's own backoff at an address lookups found
  for it (its candidate's record, or the last one kept), and only the pair
  anywhere else, such as behind a forwarder a peer named; the caller's
  deadline then charges the pair. A caller's deadline never charges an
  address lookups found for the key. Every failure the key's own history
  does not take also makes the host wait `RetryMin`, a wait that does not
  grow, before a `Connect` to any address there that lookups did not find
  for the key. A success clears its address's and its pair's backoff. A
  cancel, `Leave` or `Close` grows no backoff, and neither does a
  connection we closed ourselves (`Leave`, `Close`, or the application).
  What a peer can still do: make the swarm skip, for their backoff, the
  pairs and silent addresses it names; and hold a host for addresses no
  lookup vouched for, for as long as each dial to it runs plus `RetryMin`
  after it, again for every fresh port or key it names there. It cannot
  hold off a key at an address lookups found for it, except by occupying
  that host's one vouched dial with a forged record.
  Feeding `Connect` from peers lets them choose outbound places:
  `MaxConnectPeers` bounds that share, and the caller should bound how
  often it calls `Connect` with what peers send. A connection `Connect`
  dialed never grows its kolo-transport windows (see below).
  Errors, in the order the checks run: `ctx.Err()`; `ErrInvalidArgument`
  for a key that is not 32 bytes or is ours, IPv6 (IPv4-mapped included)
  in `addr` or `from`, an address without a port or outside the scope of
  `from`, or our own address; `ErrClosed`; `ErrInvalidArgument` for a
  topic not joined; `ErrRefused` for `Allow`; `ErrDuplicate`;
  `ErrRefused` for `MaxPeers`, the topic's `MaxPeers` or
  `MaxConnectPeers` (also when `MaxInbound` equals `MaxPeers`, which
  leaves `Connect` no place), which only peers leaving or a new
  configuration can end, or when the process has no file descriptor left for
  the dial's own UDP socket, which charges no key or address; then `ErrWait` (it wraps `ErrRefused`; retry
  later) for the key's backoff, the address's, the pair's or the host's,
  a dial to the host in progress, `MaxConnecting` dials running, or the
  dial rate. Use `errors.Is`. A key kolo-secure refuses,
  such as a small-order point, is `ErrInvalidArgument` only once the dial
  starts, so a bound reached first gives its own error; that dial gives
  its start back. After the dial: `ErrLost` (it failed; it wraps
  `kolosecure.ErrUnexpectedPeer` when another key answered),
  `ErrDuplicate`, `ErrRefused` (the peer refused, or the topic was left),
  `ErrProtocol`, `ctx.Err()` and `ErrClosed`. It blocks for up to
  kolo-transport's and kolo-secure's handshake timeouts plus
  `HelloTimeout`.
- `Conn` is the connection interface: `RemotePublicKey`, `OpenStream`,
  `AcceptStream`, `OpenUniStream`, `AcceptUniStream`, `Context`, `Close`
  and `CloseWithError`, with kolo-transport stream types.
  `*kolosecure.Conn` and `*kolorelay.Conn` satisfy it, and both prove the
  remote key before they are returned; a `Conn` of your own must do the same.
- `Peer` has `PublicKey()`, `Addr()` (the remote UDP address, or zero if
  the `Conn` has no `RemoteAddr` method), `Conn()`, `Direct()` (the
  connection came from kolo-dht or `Connect`, not through a relay or
  `Attach`), `Outbound()` (the peer holds one of our outbound places: we
  dialed its key, from a lookup or with `Connect`, or attached it as
  outbound, before it reached us; it is the direction of the place, not
  who chose the peer: in a simultaneous open the kept connection may be
  the one the peer opened, and a `Connect` place is outbound even when
  another peer supplied its address. Inbound places are capped by
  `MaxInbound` and `Connect` places by `MaxConnectPeers`, so at least
  `MaxPeers` - `MaxInbound` - `MaxConnectPeers` places are left to keys
  that lookups found; a protocol that wants outbound peers it chose itself,
  such as a gossip mesh quota, can rely on that share only) and
  `Topics()` (the topics it shares with us now, as far as the peer claimed
  them: topic hashes are not secret, so any peer can claim one, and
  `Config.Allow` is where to admit only keys you know). The peer is lost when `Conn().Context()` ends.
- `Close()` closes every peer connection (code 0) and the node, and waits
  for the swarm's goroutines. It is safe to call more than once. Every
  blocking call returns `ctx.Err()` once its context is done, and
  `ErrClosed` after `Close`.

## Public and private networks

A network is the set of kolo-dht servers that know each other, and a
node is in the network of the entry nodes it bootstraps from. With no
list at all, `Bootstrap(ctx, nil)` joins the public network through the
entry nodes built into kolo-dht (`kolodht.PublicServers`), which Ciranda
runs for everyone, so an app needs no setup. `Config.BootstrapNodes` is
empty by default; when it is set, or when you pass servers, those are used
instead.

Who learns what on the public network: the two entry nodes receive the
node's IP address and public key with the first packet, and every
public-network node it queries or that queries it sees them too. With
`Join` and `Announce`, the topic hash and the node's IP address are stored
in the public network, and anyone who looks up that topic can read them;
`Lookup` alone reveals the topic hash to the nodes it asks. Nothing hides
the address, and the entry nodes have no uptime guarantee while Kolo is a
beta.

To stay private, never rely on the default: pass your own list to
`Config.BootstrapNodes` or to `Bootstrap`. A nil list means the public
network, also when it comes from a flag, a config file or an empty
`ParseNodes` result, so check that it is not empty before the call. An
empty list that is not nil is `ErrInvalidArgument` and sends nothing, which
a private application can use as a guard, for example
`servers := []netip.AddrPort{}` before it adds its own entries.

- The public network needs no setup. Another public network, whose
  operators publish their entry nodes, is reached by putting that list in
  `Config.BootstrapNodes` (from `ParseNodes` or `LoadNodes`), or by passing
  it to `Bootstrap`.
- A private network runs its own entry nodes. Its first entry node starts
  with no list (kolo-node `run -first`, or a kolo-dht server that never
  calls `Bootstrap`), more entry nodes bootstrap from it, and every member
  lists only these entry nodes. Run at least two on hosts that stay up,
  with their UDP port open.

Host names in the list are resolved to IPv4 at each `Bootstrap`, with the
system resolver, 16 names at once and none started once 64 addresses are
held, each name within 5s and within `ctx`'s deadline: at most 8 addresses per name and 64 in all, literal addresses
first. A name's address is kept only if it is global or in the scope of
the swarm's own address (loopback, link-local or private), so a DNS answer
cannot point the swarm at a local network it was not given; on an
unspecified address such as `0.0.0.0` only global answers count. Literal
addresses are kept as configured. Names that do not resolve are skipped;
if nothing resolves, `Bootstrap` returns `ErrNoNodes`.

What it is: separation by topology. A kolo-dht server learns other
servers only from the servers it asks and from servers that send it
requests, and a lookup only asks servers learned that way, so two
networks with different entry nodes never see each other's servers,
records or peers (a test checks this with two networks on one host).

What it is not: access control. The list is not a secret. Anyone who
learns one entry address can bootstrap from it, look up topics and
announce on them, and an entry node that also knows another network's
servers joins the two. Decide who may connect with `Config.Allow` and
kolo-secure keys, admit members with kolo-invite, and trust only signed
records.

This program starts a private network on loopback: a first entry node, a
second one that joins it, and two swarms that bootstrap only from them
and connect. Run it with `go run ./examples/private`:

```go
// Command private starts a private network on loopback: two entry nodes of its own and two swarms that bootstrap
// only from them.
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

func identity() *koloid.Identity {
	id, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	return id
}

// entryNode starts a kolo-dht server; with no servers it is the first node of a new network.
func entryNode(ctx context.Context, servers []netip.AddrPort) *kolodht.Node {
	n, err := kolodht.New(ctx, "127.0.0.1:0", identity(), &kolodht.Config{Server: true})
	if err != nil {
		log.Fatal(err)
	}
	if len(servers) > 0 {
		if err := n.Bootstrap(ctx, servers); err != nil {
			log.Fatal(err)
		}
	}
	return n
}

func addr(n *kolodht.Node) netip.AddrPort { return n.Addr().(*net.UDPAddr).AddrPort() }

func connected(ctx context.Context, s *koloswarm.Swarm) *koloswarm.Peer {
	for {
		ev, err := s.Next(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if ev.Kind == koloswarm.Connected {
			return ev.Peer
		}
	}
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first := entryNode(ctx, nil)
	defer first.Close()
	second := entryNode(ctx, []netip.AddrPort{addr(first)})
	defer second.Close()

	// The list an application would read from its own config, a flag or an environment variable.
	nodes, err := koloswarm.ParseNodes(addr(first).String() + "," + addr(second).String())
	if err != nil {
		log.Fatal(err)
	}
	topic := koloswarm.Topic(sha256.Sum256([]byte("kolo private example")))
	var swarms []*koloswarm.Swarm
	for range 2 {
		s, err := koloswarm.New(ctx, "127.0.0.1:0", identity(), &koloswarm.Config{BootstrapNodes: nodes})
		if err != nil {
			log.Fatal(err)
		}
		defer s.Close()
		if err := s.Bootstrap(ctx, nil); err != nil {
			log.Fatal(err)
		}
		if err := s.Join(ctx, topic, nil); err != nil {
			log.Fatal(err)
		}
		swarms = append(swarms, s)
	}
	p := connected(ctx, swarms[0])
	connected(ctx, swarms[1])
	fmt.Printf("private network: %d entry nodes, connected to %x\n", len(nodes), p.PublicKey()[:8])
}
```

```text
$ go run ./examples/private
private network: 2 entry nodes, connected to <16 hex characters>
```

The same network with kolo-node, on loopback, with the keys in a new
temporary directory:

```sh
dir=$(mktemp -d)
kolo-node run -listen 127.0.0.1:7447 -identity "$dir/a/node.key" -first
kolo-node run -listen 127.0.0.1:7448 -identity "$dir/b/node.key" -bootstrap 127.0.0.1:7447
```

Members then list both entry nodes, for example in a file read with
`LoadNodes`:

```text
# entry nodes of our network
127.0.0.1:7447
127.0.0.1:7448   # second entry node
```

## Relay fallback

Two peers whose direct `Connect` fails, for example two computers behind
firewalls that let only outgoing traffic through, can meet through a
[kolo-relay](https://github.com/ciranda-dev/kolo-relay). The relay
copies encrypted bytes: each side runs its own kolo-secure connection end
to end through it, so the relay never sees plaintext, and the target
proves its key as on a direct connection.

Relays are a network setting, like the entry nodes: `Config.Relays` is an
ordered list of `Relay` values (`Addr`, `PublicKey`), empty
by default, and with an empty list the swarm runs no relay code at all.
`ParseRelays` and `LoadRelays` read the list as `host:port@key`, the key
as 64 hex characters, with the rules of `ParseNodes` and `LoadNodes`:

```text
# relays of our network
203.0.113.20:7448@<64 hex characters>
relay.example.org:7448@<64 hex characters>   # resolved to IPv4 at each use
```

`New` checks each entry: an IPv6 address in any form, port 0, a bad name,
a key that is not 32 bytes or is our own, one key at two
addresses or one address with two keys is `ErrInvalidConfig`, naming the
entry's position; an exact duplicate is dropped. A name is resolved at
each use with the rule of entry nodes, and its first usable address is
used, so a relay name must point to one relay process.

How two peers meet:

- A peer that announces a topic keeps a reservation at every listed
  relay, taken before `Join` announces, so a peer that finds the fresh
  record can reach it at once. A swarm that joins topics with `Lookup`
  only holds no reservation. After the last announced `Leave`, the swarm
  closes its reservations, and with them every inbound relayed peer that
  came through them, also one that still shares a `Lookup`-only topic.
- Two peers meet through any relay that both list, identified by its
  key; the lists need not share an order. A dialer cannot learn where
  the other side reserved, so it tries its relays one at a time: the one
  that carried that key last, then list order, skipping relays known
  down. A relay where the target holds no reservation answers at once,
  and the dialer moves to its next relay.
- Lists that share no relay give no relayed connection: the key backs off
  and `Unreachable` comes, as for a peer that is offline. Applications
  that need it compare lists over an authenticated message after first
  contact.
- On first contact the relays are tried once the direct `Connect` failed
  (not when it answered try later), or once it ran for kolo-dht's punch
  window of two consistent mappings, 10s of probes plus twice
  `DHT.RequestTimeout` (12s at the defaults), whichever comes first. That
  `Connect` keeps running, and if it connects, the direct connection
  replaces the relayed one. A key that needed a relay
  before is dialed directly and through its relays at once, so a pair
  whose relayed session ended comes back after one relay dial, and a
  direct connection that succeeds replaces the relayed one (`Lost` with
  `ErrDuplicate`, then `Connected` with `Direct()` true).
- First contact through a relay therefore takes at most the punch window
  (12s) plus one relay dial of at most 60s per relay tried, 72s with one
  relay that connects, when punches start but never connect.

Relayed connections use the swarm's own `DHT.Secure` settings, its
`Transport` included, so a relayed connection has the same stream limits
and windows as a direct one. The swarm's kolo-transport `AcceptFunc`
does not filter relayed connections, since kolo-relay sets that field
itself; `Allow` does, with a zero address, before the end-to-end
handshake. Relayed inbound peers count against `MaxInbound`, `MaxPeers`,
`MaxHandshakes`, and `MaxHandshakesPerIP` by relay key.

A relayed `Peer` has `Direct()` false and a zero `Addr()`; its `Conn()`
is a `*kolorelay.Conn` whose `RelayPublicKey()` names the relay. The
hello has its 2s windows on a relayed path too, and both sides start it
at once, so it completes when the relayed round trip is well below 2s.

`RelayChanged` reports each listed relay's reservation: `Err` nil when it
is held, then `kolorelay.ErrNotAllowed`, `kolorelay.ErrLimit`,
`kolorelay.ErrReservationEnded` (the relay ended it; the swarm reserves
again, after `RetryMin` when its lifetime passed, with backoff
otherwise), `kolosecure.ErrUnexpectedPeer` (another key answered),
`ErrInvalidConfig` (the key cannot be used, such as a small-order key;
that relay is no longer used), `ErrClosed` (no announced topic is
joined) or `ErrLost`. A relay that fails without an answer is marked
down: relay dials skip it, except one probe per backoff period, and
`Join` does not wait for it. Relay dials are counted apart from kolo-dht
`Connect` calls, at most `MaxConnecting` at once, so a slow relay never
holds up direct dials. A key whose `Connect` failed while all of them ran
is not tried through the relays this time: it counts as try later, with
no `Unreachable`, and its next dial runs directly and through the relays
at once.

Every listed relay operator learns the keys, addresses and online times
of the members that announce while they list it, which keys talk through
it, when and how much, and the target key of every relay dial. It learns
no topic and no content. With kolo-node, `kolo-node relay` runs a relay
and `kolo-node check -relay` checks one from the machine it runs on.

## Addresses and filtering

kolo-swarm is IPv4 only and IPv6 input is refused: an IPv6 address,
IPv4-mapped included, given to `New`, `Bootstrap`, `Attach` or `Connect`
is `ErrInvalidArgument`, and a lookup record or kolo-dht connection with
one is dropped before `Allow` sees it.

`Connect` dials `addr` only if it is global or in the scope of `from`, the
peer that supplied it, and only a global `addr` when `from` is zero, as
kolo-dht does for addresses learned from others; the tests on loopback
pass 127.0.0.1 as `from`. `Allow` sees `addr` before the dial.

`Allow` is asked before every dial, and for every new connection before
its hello. Before a dial, `addr` is the record's `Addr`, the address the
freshest server that returned the record saw. kolo-dht's `Connect` may
also probe and dial the older addresses that up to two other servers
stored for that key, each global or in the same scope as its server;
`Allow` does not see those. For a new connection, `addr` is its remote
address, zero when the `Conn` has none. `Allow` must be fast and safe for
concurrent use. A ban list is a map behind `Allow`, and
`Peer.Conn().Close()` ends a current connection.

On loopback every peer is one host for the per-address limits of kolo-dht
and kolo-transport (requests and records per IP at a server,
`MaxConnsPerIP`). Tests with many local peers must raise them.

## Faster transfers for admitted peers

A kolo-transport stream moves at most one window per round trip, and the
windows start small for every connection because a hostile peer can make an
application hold memory for unread data. kolo-transport can grow them for a
connection the application marks as trusted (see its guide, "Faster transfers
for trusted peers"), and it never learns who a peer is. The swarm marks a
connection once `Allow` has admitted its peer, so growth is for the peers you
chose:

```go
cfg := &koloswarm.Config{
	DHT: &kolodht.Config{Secure: &kolosecure.Config{Transport: &kolotransport.Config{
		WindowGrowth:           true,
		MaxStreamReceiveWindow: 256 << 10,
		MaxConnReceiveWindow:   256 << 10, // equal, so a connection nobody marked keeps exactly the old windows
	}}},
	Allow: func(key ed25519.PublicKey, addr netip.AddrPort) bool { return paired[string(key)] },
}
```

- Growth is granted to every connection `Allow` admitted, on the accepted
  path, the dialed path and `Attach`, once the swarm has made it a `Peer`. For
  an application whose `Allow` is a pairing list that is the paired peer
  only.
- A connection `Allow` refused, or that the swarm did not admit for another
  reason (no shared topic, full), is never marked.
- With no `Allow` there is no trust decision, so the swarm marks nothing and
  no connection grows, even with `WindowGrowth` on.
- A relayed connection, which has no `AllowWindowGrowth` method, is never
  marked.
- A connection `Connect` dialed is never marked: it has its own UDP socket
  and kolo-transport connection, so its growth would come out of a
  `MaxGrownMemory` of its own, outside the node's (kolo-dht has no dial
  from the node's socket that would share it). A connection that reached
  us and took a `Connect` place is marked as any accepted one.
- `WindowGrowth` is off by default and then no window grows. The swarm only
  passes `DHT.Secure.Transport` on; when it derives `MaxMemory` (a zero
  value) it adds the growth `MaxGrownMemory` allows (64 MiB by default), so
  kolo-transport's memory check still passes at any `MaxPeers`. With
  `MaxPeers` zero the check runs the other way: `MaxPeers` is the most
  places whose windows fit in `MaxMemory` (1258 at the defaults, 1173 with
  growth).

## Errors

Errors, for `errors.Is`; none carries anything a peer sent:

- `ErrInvalidConfig`: a field is out of range. A kolo-dht config error is
  wrapped, so its own sentinel matches too.
- `ErrWait`: `Connect` was refused for now (a backoff, the dial rate, a
  dial to the host in progress, `MaxConnecting` dials running); it wraps
  `ErrRefused`, so both match.
- `ErrInvalidArgument`, `ErrClosed`, `ErrRefused`, `ErrDuplicate`,
  `ErrProtocol`, `ErrLost` (see above).

