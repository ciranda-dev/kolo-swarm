# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `Config.MaxPeers` defaults to 0, which derives it from kolo-transport's memory check, the most places whose receive windows fit `MaxMemory`: 1258 at the defaults (1173 with `WindowGrowth`), where it was 64, and 87274 at kolo-transport's largest `MaxMemory` of 64 GiB; its maximum of 1024 is gone, and a positive value is a cap of the application. `MaxInbound` (629) and `MaxConnectPeers` (314) stay ratios of it. The derived kolo-transport `MaxDialed` is 1338 (was 144) and `MaxConns` 709 (was 112), `MaxMemory` stays 1 GiB. A default swarm holds and accepts about 20 times more connections.
- **Breaking:** `Config.MaxTopics` defaults to 0, no cap, where it was 16 and could not exceed 32; `Join` past 16 topics no longer returns `ErrInvalidArgument`. With `MaxTopics` 0, `DHT.MaxAnnouncements` must be 0 (kolo-dht without its ceiling); a positive value is `ErrInvalidConfig`.
- **Breaking:** `JoinOptions.MaxPeers` defaults to no cap of its own. A topic may use any free place and, when places run out, is kept a fair share of `MaxPeers` (its limit or `MaxPeers` / J if lower, for J joined topics) and, with `Lookup`, 6 outbound places that our own lookups chose. A dial for a topic below that may close a connected peer (not one in a hello or a `Connect` place in use, and none that would drop another topic below its share): inbound peers first, then `Connect` places, then outbound peers, the newest first. The peer sees code 3 (`ErrRefused`), our `Lost` carries `ErrClosed`, and its key's backoff is not charged.
- **Breaking:** `Config.MaxCandidates` defaults to 0, the larger of 1024, 64 per joined topic and `MaxPeers`, where it was 1024; its maximum of 32768 is gone and a positive value, from 16 up, is a fixed total.
- **Breaking:** a `Config` that sets `DHT.MaxAnnouncements` and leaves `MaxTopics` at 0 is `ErrInvalidConfig`; a v0.1.0 `Config` could set it alone, since `MaxTopics` was 16 by default. Set `MaxTopics` with it.
- **Breaking:** `ParseNodes`, `LoadNodes`, `ParseRelays`, `LoadRelays`, `Config.BootstrapNodes` and `Config.Relays` accept more than 16 entries. Name resolution runs 16 names at once and starts none once 64 addresses are held.
- `Join` with `Announce` paces first announcements (a burst of 10, then 10 a second) and retries `kolodht.ErrNotStored` 3 times with jittered backoff from 1s, so it can take up to about 14s longer and no longer fails when many topics are joined at once.
- A peer is counted on every topic our lookups found it on, also past the 32 a hello carries, and `Peer.Topics` can list more than 32 topics. A hello lists first the topics furthest below their fair share.
- `Swarm.Connect` returns `ErrRefused` (limit reached) when the process has no file descriptor left for the dial's socket, and charges no key, address or host.
- On first contact with a key, the relays in `Config.Relays` are now also tried once the direct kolo-dht `Connect` ran for the punch window of two consistent mappings (10s of probes plus twice `DHT.RequestTimeout`, 12s at the defaults), not only after it failed, which could take 3 × `PunchTimeout` (135s). The `Connect` keeps running and a direct connection still replaces the relayed one. First contact through one relay now takes at most 72s instead of 195s.
- The connection to each relay in `Config.Relays` now uses the swarm's `DHT.Secure.Transport` congestion controller and receive windows (before: Reno and kolo-transport's default windows), with kolo-relay's 5s keep-alive.
- The connection to each relay in `Config.Relays` offers QUIC datagrams only when `Config.RelayDatagrams` is set; then a relay of kolo-relay's protocol version 1 carries the relayed packets as datagrams and a loss on that leg reaches the end-to-end connection as a loss, not a delay. Without it the leg speaks version 0, packets on the stream. It is apart from `DHT.Secure.Transport.Datagrams`, which is for the direct connections.

### Added

- `Config.RelayDatagrams` (default false), see above.
- `BenchmarkTally`, the cost of counting the places of every topic under the swarm lock, and a "Heap" section in `docs/limits.md` with the totals at the new defaults and the hostile worst case.

### Fixed

- With `DHT.Secure.Transport.Datagrams` on, the derived `MaxPeers`, `MaxDialed`, `MaxConns` and `MaxMemory` count the 240 KiB of datagram queues kolo-transport's `MaxMemory` check adds per connection, so a default swarm with datagrams derives 822 places (`MaxDialed` 902, `MaxConns` 491) and starts; with that kolo-transport check it was refused with `ErrInvalidConfig`. A swarm with datagrams and a positive `MaxPeers` gets a `MaxMemory` raised to cover the queues.
- `Leave` no longer closes a peer that our lookups found on another joined topic, when the hello had not listed it; the topics of such a peer are refilled from our lookups.
- A key found on several topics keeps the record of each, and a dial that fails with `ErrUnreachable` through the record of a topic the peer has left is no failure of the key while another record has not failed, so the key is redialed through a topic it still announces and not left to backoff for a lookup interval.
- A reply to a hello that lists more than 32 shared topics is cut to the 32 the wire carries, with the topics the hello listed first; it was refused as too long.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-swarm.
