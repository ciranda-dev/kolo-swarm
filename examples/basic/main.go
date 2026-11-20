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
