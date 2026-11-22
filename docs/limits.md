# Limits

Every option, default and bound of kolo-swarm, with the reason for it.

## Config

`Config`: nil or a zero field means the default, and a value out of range
is `ErrInvalidConfig`.

| Option | Default | Range | Why |
|---|---|---|---|
| `DHT` (passed to `kolodht.New`) | nil: kolo-dht's defaults, with `MaxAnnouncements` = `MaxTopics` and the three kolo-transport rows below | see kolo-dht; `MaxAnnouncements` at least `MaxTopics` | Protocol: the node announces every joined topic |
| `MaxPeers` (connected peers plus dials in progress) | 64 | 1 to 1024 | Memory: inbound peers count too, so one bound covers the node |
| `MaxInbound` (peers that connected to us) | `MaxPeers`/2 rounded up: 32 | 1 to `MaxPeers` | Security: half the slots stay outbound places (lookups or `Connect`), against eclipse attacks (Heilman et al.) |
| `MaxConnectPeers` (places `Swarm.Connect` holds: dials whose key has not proved itself yet, and the slots they became, an inbound connection that took one included) | `MaxPeers`/4, at least 1 and at most `MaxPeers` - `MaxInbound`: 16 (a derived default) | 1 to `MaxPeers` - `MaxInbound`; must be unset when `MaxInbound` equals `MaxPeers`, and `Connect` is then always refused | Security: peers that feed `Connect` choose these outbound places, so at least `MaxPeers` - `MaxInbound` - `MaxConnectPeers` places (16 at the defaults) stay with keys lookups found |
| `JoinOptions.MaxPeers` (per topic) | `MaxPeers` | 1 to `MaxPeers` | Security: bounded by `MaxPeers`; inbound peers take at most ceil(topic `MaxPeers` × `MaxInbound` / `MaxPeers`) of a topic's places, 32 of 64 at the defaults |
| `MaxTopics` (joined at once) | 16 | 1 to 32 | Memory: bounds lookup loops and announcements; a HELLO carries at most 32 topics |
| `MaxConnecting` (kolo-dht `Connect` calls at once, and separately relay dials and `Swarm.Connect` dials; also `Swarm.Connect` dial starts per `RetryMin`) | 3 | 1 to 16 | Memory: bounds kolo-dht dials, relay dials and direct dials in progress; a failed `Connect` that finds no relay dial free counts as try later; `Swarm.Connect` dials have their own count, so addresses learned from peers never take the dials of keys found by lookups |
| `MaxHandshakes` (hellos in progress; a quarter kept for `Attach`, another for known keys) | 16 | 1 to 256 | Security: a hello holds its slot for at most 2s (4s on the side that is not the arbiter), so 16 admit at least 4 a second even from silent peers |
| `MaxHandshakesPerIP` (hellos in progress from one source, see [protocol.md](protocol.md)) | 4, or `MaxHandshakes` if lower | 1 to `MaxHandshakes` | Security: equal to kolo-transport's `MaxConnsPerIP`, so one address cannot hold every hello |
| `MaxCandidates` (keys from lookups over all topics, split equally between joined topics; also bounds the dropped keys whose backoff state is kept, `Swarm.Connect` keys among them, at most twice it, and each of `Swarm.Connect`'s address, pair and host tables, which grow to twice it and are trimmed to it) | 1024 | 16 to 32768 | Memory: bounds what lookups can make us hold; 1024 gives each of `MaxTopics` (16) joined topics a share of 64, one topic's `MaxPeers` |
| `MaxEvents` (queued `Found`, and separately queued `Unreachable`) | 64 | 16 to 4096 | Memory: these events are hints dropped when full, and `Connected` and `Lost` are never dropped |
| `HelloTimeout` | 10s | 1s to 60s | Security: bounds how long a whole hello can take |
| `LookupInterval` | 10m, plus up to a fifth of it at random | 1s to 1h | Protocol: the lookup at `Join` finds the peers already there, so the interval only delays finding peers that join later |
| `RetryMin` | 1s | 100ms to 1m | Security: the backoff floor, so a failing key is never redialed at once; also the period of `Swarm.Connect`'s dial rate and host wait, so raising it slows `Connect` |
| `RetryMax` | 10m | `RetryMin` to 1h | Protocol: in step with `LookupInterval` |
| backoff growth (fixed) | `RetryMin` + uniform[0, min(`RetryMax`, `RetryMin`·2^n) − `RetryMin`) | fixed | Security: exponential with full jitter, so a key that keeps failing is dialed with growing delays |
| lasting connection (resets the failure count) | 15s | fixed | Security: a connection that ends sooner counts as a failure |
| hello window (each step of the hello, see `Attach`) | 2s, or `HelloTimeout` if shorter | fixed | Security: bounds how long a silent peer holds a hello |
| hellos at once per key | 2 | fixed | Security: a simultaneous open needs 2; more would let one key fill the hellos |
| HELLO and REPLY size | 1026 and 1044 bytes, at most 32 topics | fixed | Protocol: the wire format's bound, checked before decoding |
| kolo-transport `MaxDialed`, when zero | `MaxPeers` + `MaxHandshakes` + kolo-secure `MaxPending`, at least 32: 144 | kolo-transport's | Protocol: covers our dials and the connections kolo-dht dials to answer a punch, which become inbound peers, hellos or queued connections |
| kolo-transport `MaxConns`, when zero | `MaxInbound` + `MaxHandshakes` + kolo-secure `MaxPending`, at least 100: 112 | kolo-transport's | Protocol: covers inbound peers, hellos and kolo-secure handshakes |
| kolo-transport `MaxMemory`, when zero | (`MaxConns` + `MaxDialed`) × `MaxConnReceiveWindow`, plus `MaxGrownMemory` (64 MiB by default) when `WindowGrowth` is on, at least 1 GiB | kolo-transport's | Protocol: keeps kolo-transport's window check passing at any `MaxPeers`, with or without growth |
| `Allow func(key, addr) bool` | nil (allow all) | false or a panic refuses | Security: a ban list or filter; `addr` is IPv4 or zero |
| `BootstrapNodes` | empty | at most 16 entries | Security: each name is a DNS query at every `Bootstrap`, and 16 entry nodes are more than a network needs to stay reachable; equal to kolo-node's `maxEntries`, so one list works in both |
| addresses per bootstrap name (fixed) | 8 | fixed | Protocol: a name may front several entry nodes; kolo-node's `maxPerEntry` |
| bootstrap addresses in all (fixed) | 64 | fixed | Protocol: kolo-dht's `maxBoot`, the most servers its `Bootstrap` pings, so none is dropped there |
| name resolution (fixed) | 5s per name, in parallel, within `ctx` | fixed | Security: a slow or silent resolver cannot hold `Bootstrap`; kolo-node's resolve timeout |
| name answers kept (fixed) | global, or in the scope of the swarm's address | fixed | Security: kolo-dht's rule for addresses learned from others, so DNS cannot point the swarm at a local network |
| `LoadNodes` file size (fixed) | 64 KiB | fixed | Security: bounds what a wrong path can make it read; 16 entries of the longest form (a 253-byte name, a colon and a 5-digit port) take about 4 KiB, the rest leaves room for comments |
| `Relays` | empty: no relay | at most 16 entries | Security: each listed relay costs a reservation while an announced topic is joined; the same cap as `BootstrapNodes` |
| per listed relay, while an announced topic is joined (fixed) | one reservation connection (two for up to the relay's `MaxSessionDuration` after a lifetime end), kolo-relay's 5s keep-alive, one renewal per `ReservationLifetime`, one goroutine | fixed | Protocol: a dialer cannot learn where the target reserved, so the target reserves at every relay it lists |
| relayed connection settings (fixed) | `DHT.Secure` and its `Transport`, for every relay | fixed | Protocol: a relayed connection has the stream limits and windows of a direct one |
| relay connection settings (fixed) | the connection to each relay has the swarm's `DHT.Secure.Transport` `CongestionControl`, `MaxStreamReceiveWindow`, `MaxConnReceiveWindow` and `Datagrams`, a 5s keep-alive; no window growth | fixed | Protocol: the relay carries the session's packets as QUIC datagrams when the swarm's transport sets `Datagrams` and the relay offers them too, else as frames on one stream of that connection, so its controller and windows set the relayed speed; kolo-relay never allows growth on it. Memory: with `Datagrams`, datagrams add about 240 KiB of heap per relay connection (kolo-transport limits, datagram queues) and about 192 KiB per relayed session (kolo-relay limits) |
| first reservations before `Announce` (fixed) | in parallel, at most 40s: 10s + 10s handshakes and kolo-relay's 20s `ControlTimeout` | fixed | Protocol: a peer that finds the fresh record can reach us at once |
| reservation after its lifetime passed (fixed) | `RetryMin` | fixed | Protocol: a lifetime end is not a failure |
| reservation after a failure (fixed) | backoff from `RetryMin` to `RetryMax` per relay, reset by a reservation that lasted 15s | fixed | Security: a relay that refuses, or a second process with our key, is retried with growing delays |
| relay dials at once | `MaxConnecting`, over all relays, apart from kolo-dht `Connect` calls | as `MaxConnecting` | Security: a slow relay never holds up direct dials |
| `Swarm.Connect` bounds | the bounds of a dial from a lookup (`Allow`, `MaxPeers`, the topic's `MaxPeers`, the key's own backoff, one dial in progress per host), `MaxConnectPeers` places, `MaxConnecting` dials at once (hellos of proved dials included); at an address lookups found for the key, dials there that no lookup vouched for do not count, but one vouched dial at most runs per host; a dial whose key has not proved itself holds no place of the key | as those options | Security: within these, a caller that feeds it addresses from peers takes at most `MaxConnectPeers` places, never redials a key in its own backoff, and a false address for a key never stands in the way of that key |
| `Swarm.Connect` dial starts | `MaxConnecting` per `RetryMin`, refilled in proportion: 3 a second at the defaults (a derived default); a start kolo-secure refused before sending is given back | through `MaxConnecting` and `RetryMin` | Security: bounds the packets peers can make the swarm send to addresses they name |
| `Swarm.Connect` backoff | before the key proved itself: no answer or a timeout backs off the address (host and port) and the pair of key and address, another key answering the pair, the caller's deadline the address; after it proved itself: a failed hello or a lost connection backs off the key's own history at an address lookups found for it, else the pair, and the caller's deadline the pair; the caller's deadline never charges an address lookups found for the key, and the address's backoff holds off only keys lookups did not find there; a connection we closed ourselves (Leave, Close, the application) charges nothing; every failure the key's own history does not take makes the host wait `RetryMin` (not growing) for addresses lookups did not find for the key. From `RetryMin` to `RetryMax` as for keys; the address, pair and host tables grow to twice `MaxCandidates` entries each and are trimmed to `MaxCandidates`; a success clears its address and pair | through `RetryMin`, `RetryMax`, `MaxCandidates` | Security: a false address for a key, a forwarder included, never charges the key's own backoff; a peer naming many keys or ports at one host gets it dialed at most once per dial plus `RetryMin`, for addresses no lookup vouched for |
| `Swarm.Connect` addresses (fixed) | IPv4 with a port, global or in the scope of `from`: loopback for loopback, link-local for link-local, 10/8, 172.16/12 and 192.168/16 for any of them, 100.64/10 only for 100.64/10; global only when `from` is zero (unknown source, such as a relayed or attached peer); not our own socket, nor a loopback or interface address at its port when it listens on every address | fixed | Security: kolo-dht's rule for addresses learned from others, with carrier-grade NAT apart, so a remote peer cannot point the swarm into a local network or at itself; a public address a NAT maps to us is not known here |
| one relay dial (fixed) | at most 60s: 10s + 10s outer handshakes, 20s `ControlTimeout`, 10s + 10s end-to-end handshakes at the defaults | fixed | Protocol: kolo-relay's and kolo-secure's own bounds |
| relays of one dial (fixed) | one at a time, the last that carried the key first, then list order; down ones skipped | fixed | Security: a key costs at most one relay session at a time |
| down relay probe (fixed) | one at a time per relay, backoff from `RetryMin` to `RetryMax` | fixed | Security: a dead or blackholed relay costs one dial per backoff period, not one per key |
| relayed inbound hellos | `MaxHandshakesPerIP` per relay key, within `MaxHandshakes` | as those options | Security: one relay cannot hold every hello |
| `RelayChanged` queued (fixed) | the newest per relay | fixed | Memory: only each relay's current state matters |
| `LoadRelays` file size (fixed) | 64 KiB | fixed | Security: the `LoadNodes` bound |

Memory: the swarm holds at most `MaxCandidates` candidates plus the
backoff state of up to twice as many dropped keys, `MaxPeers` peers,
`MaxHandshakes` hellos, and 2 × `MaxPeers` + 2 × `MaxEvents` events, plus one
`RelayChanged` per listed relay. Connection memory is
kolo-transport's: up to `MaxConns` + `MaxDialed` connections (256 at the
defaults), each with the worst case per connection given in
kolo-transport's limits page. With `Config.Relays` set, connections outside
those limits add to it: each listed relay's reservation connection (two for
a while after a lifetime end) while an announced topic is joined, and per
relayed peer an end-to-end kolo-transport connection with `DHT.Secure`'s
settings, plus, when we dialed it, its own relay connection and UDP socket;
`MaxPeers` bounds the relayed peers and `MaxConnecting` the relay dials.
A `Swarm.Connect` connection is outside kolo-transport's `MaxConns` and
`MaxDialed` too: it has its own UDP socket and kolo-transport connection
with `DHT.Secure`'s settings, never marked for window growth;
`MaxConnecting` bounds their dials and `MaxPeers` the connections, of
which `MaxConnectPeers` bounds those in places `Connect` made (a direct
`Connect` that replaces a relayed peer keeps that peer's place, which
was already counted, so it adds no place). Size those options to the memory the process may
use, and set `GOMEMLIMIT` a little below it.

