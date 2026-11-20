# kolo-swarm

Join a Kolo topic and keep connections to the peers found on it.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-swarm keeps connections to the peers of a topic, preferring direct paths and using a relay last, as [ICE (RFC 8445)](https://www.rfc-editor.org/info/rfc8445) does, and bounds connections per address against the eclipse attacks described by [Heilman et al.](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman)

A `Swarm` runs its own [kolo-dht](https://github.com/ciranda-dev/kolo-dht) node. It announces and looks up the topics it joined, dials the peers it finds with backoff and jitter, accepts the peers that dial it, and keeps at most one [kolo-secure](https://github.com/ciranda-dev/kolo-secure) connection per remote key, within fixed limits on peers, inbound peers, dials and handshakes.

It uses relays only when `Config.Relays` lists some: then a peer it cannot reach directly is dialed through a [kolo-relay](https://github.com/ciranda-dev/kolo-relay) that both peers list, still end to end encrypted. `Connect` dials a known key at a known address, such as one another peer supplied. A connection the application opened another way enters through `Attach`, and it must already authenticate the remote key, as kolo-secure does.

It is Go only and builds without cgo. It is IPv4 only: IPv6 input is refused with `ErrInvalidArgument`.

## Install

```sh
go get github.com/ciranda-dev/kolo-swarm
```

## Quick start

A kolo-dht server and two swarms on loopback join one topic, connect and echo a message.

```go
// Command basic runs a kolo-dht server and two swarms on loopback that join one topic, connect, and echo a message.
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	koloswarm "github.com/ciranda-dev/kolo-swarm"
)

func swarm(ctx context.Context, server netip.AddrPort) *koloswarm.Swarm {
	id, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	s, err := koloswarm.New(ctx, "127.0.0.1:0", id, nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := s.Bootstrap(ctx, []netip.AddrPort{server}); err != nil {
		log.Fatal(err)
	}
	return s
}

// connected waits for the first Connected event of s.
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

	sid, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	server, err := kolodht.New(ctx, "127.0.0.1:0", sid, &kolodht.Config{Server: true})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	saddr := server.Addr().(*net.UDPAddr).AddrPort()

	alice, bob := swarm(ctx, saddr), swarm(ctx, saddr)
	defer alice.Close()
	defer bob.Close()

	topic := koloswarm.Topic(sha256.Sum256([]byte("kolo example topic")))
	if err := bob.Join(ctx, topic, &koloswarm.JoinOptions{Announce: true}); err != nil {
		log.Fatal(err)
	}
	if err := alice.Join(ctx, topic, &koloswarm.JoinOptions{Lookup: true}); err != nil {
		log.Fatal(err)
	}
	pa, pb := connected(ctx, alice), connected(ctx, bob)
	fmt.Printf("alice connected to %x (direct %v)\n", pa.PublicKey()[:8], pa.Direct())

	go func() {
		st, err := pb.Conn().AcceptStream(ctx)
		if err != nil {
			return
		}
		io.Copy(st, st)
		st.Close()
	}()
	st, err := pa.Conn().OpenStream(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := st.Write([]byte("hello kolo")); err != nil {
		log.Fatal(err)
	}
	st.Close()
	reply, err := io.ReadAll(st)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s from %x\n", reply, pa.PublicKey()[:8])
}
```

```text
$ go run .
alice connected to <16 hex characters> (direct true)
hello kolo from <16 hex characters>
```

A real deployment bootstraps from a few kolo-dht servers, such as kolo-node: a public network's published list, or entry nodes of your own for a private network. With no list at all (a nil slice and no `Config.BootstrapNodes`), `Bootstrap` joins the public network: the entry nodes built into kolo-dht, run by Ciranda, learn your IP address and public key, and an announced topic hash and your IP address become visible there. To stay private, pass your own list; see [Public and private networks](docs/guide.md#public-and-private-networks).

## API

| Symbol | What it does |
|---|---|
| `New` | Open a kolo-dht node as an identity and start the swarm |
| `Swarm.Bootstrap` | Ping kolo-dht servers and fill the routing table |
| `ParseNodes`, `LoadNodes`, `Config.BootstrapNodes` | Parse bootstrap nodes (`host:port`, IPv4 or a host name) from a comma-separated list or a file, for `Bootstrap` to use when given no servers |
| `Swarm.Join`, `Swarm.Leave` | Join a 32-byte topic to announce it, look it up, or both; stop and close peers that share no other topic |
| `Swarm.Next` | Return the next event: `Found`, `Connected`, `Unreachable`, `Lost` or `RelayChanged` |
| `Swarm.Attach` | Hand the swarm a connection the application opened itself |
| `Swarm.Connect` | Dial a known key at a known IPv4 address for a joined topic, given the peer that supplied the address, within the limits of any dial and its own (`MaxConnectPeers`, a dial rate, a backoff per address and pair, a wait per host) |
| `Relay`, `Config.Relays`, `ParseRelays`, `LoadRelays` | List the kolo-relays (`host:port@key`) used when a direct connection fails, from a comma-separated list or a file |
| `Peer` | A connected peer: `PublicKey`, `Addr`, `Conn`, `Direct`, `Outbound` (holds one of our outbound places) and `Topics` (the topics the peer claimed; use `Allow` to admit only keys you know) |
| `Conn` | The connection interface; `*kolosecure.Conn` and `*kolorelay.Conn` satisfy it |
| `Config`, `JoinOptions` | Peer, topic, handshake and retry limits, and the `Allow` filter; with `DHT.Secure.Transport.WindowGrowth` on, the connections `Allow` admits can grow their windows ([guide](docs/guide.md#faster-transfers-for-admitted-peers)) |

Errors are sentinels for `errors.Is`: `ErrInvalidConfig`, `ErrInvalidArgument`, `ErrClosed`, `ErrRefused` (with `ErrWait` when `Connect` should retry later), `ErrDuplicate`, `ErrProtocol` and `ErrLost`.

## Documentation

- [Guide](docs/guide.md): every call, events, public and private networks, relay fallback, addresses and filtering, and errors.
- [Limits](docs/limits.md): every option with its default, range and reason, and memory.
- [Protocol and design](docs/protocol.md): deduplication, limits and backoff, the hello format, close codes and references.

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
