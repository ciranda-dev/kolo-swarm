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
