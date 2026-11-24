# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- On first contact with a key, the relays in `Config.Relays` are now also tried once the direct kolo-dht `Connect` ran for the punch window of two consistent mappings (10s of probes plus twice `DHT.RequestTimeout`, 12s at the defaults), not only after it failed, which could take 3 × `PunchTimeout` (135s). The `Connect` keeps running and a direct connection still replaces the relayed one. First contact through one relay now takes at most 72s instead of 195s.
- The connection to each relay in `Config.Relays` now uses the swarm's `DHT.Secure.Transport` congestion controller and receive windows (before: Reno and kolo-transport's default windows), with kolo-relay's 5s keep-alive.
- The connection to each relay in `Config.Relays` offers QUIC datagrams only when the swarm's `DHT.Secure.Transport` sets `Datagrams`, like its controller and windows; then a relay of kolo-relay's protocol version 1 carries the relayed packets as datagrams and a loss on that leg reaches the end-to-end connection as a loss, not a delay. Without it the leg speaks version 0, packets on the stream.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-swarm.
