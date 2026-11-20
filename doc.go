// Package koloswarm joins Kolo topics and keeps connections to the peers found on them.
//
// A Swarm owns a kolo-dht node. It announces and looks up the topics it joined, dials the peers it finds with
// backoff, accepts the peers that dial it, and keeps at most one kolo-secure connection per remote key, within
// fixed limits on peers, inbound peers, dials and handshakes. It uses relays only when Config.Relays lists some:
// then a peer it cannot reach directly is dialed through a kolo-relay that both peers list. Connect dials a known key
// at a known address, and a connection the application opened another way enters through Attach.
//
// Bootstrap with no servers and no Config.BootstrapNodes joins the public network: Ciranda's entry nodes learn the
// node's IP address and public key, and an announced topic hash and IP address become visible there. Pass an explicit
// list to stay private.
//
// v0.1.x is IPv4 only, and IPv6 input, IPv4-mapped included, is refused with ErrInvalidArgument.
//
// Experimental: the API may change before v1.0.0.
package koloswarm
