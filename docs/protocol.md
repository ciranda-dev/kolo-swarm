# Protocol and design

## Design

- The swarm owns its kolo-dht node. It must be the only caller of
  `Accept`, `Announce` and `Unannounce`, and it needs its own key for
  dedup.
- One connection per remote key, shared by every topic. The hello says
  which topics a connection is for, so inbound peers count against
  per-topic limits and `Leave` can close them. A connection that shares no
  joined topic is refused.
- A peer's topics, on each side: (topics our lookups found it on ∪ the
  topic of our `Connect` dial of it ∪ topics in its hello) ∩ topics we
  joined. A peer learns only the topics it announced or put in its own
  hello, that we looked it up on them, and the topic we dialed it for.
- Dedup: the smaller key (byte order) arbitrates. It reads the other
  side's hello, admits or refuses the connection, and answers only on the
  connection it keeps, with a generation: a random 64-bit epoch drawn at
  `New` and a counter that grows with every connection it keeps. The
  newest admitted connection wins, and the older one is closed with code
  2. The other side keeps only a connection the arbiter answered on. Of two
  replies from one epoch it keeps the higher counter, so replies that
  arrive out of order cannot close both connections. A reply from another
  epoch (the arbiter restarted) replaces the older connection. A rule
  based on the dialer would not work: kolo-secure does not expose who
  dialed, and kolo-dht can hand a `Connect` caller the connection the peer
  dialed.
- A connection from `Attach` or through a relay never replaces one from
  kolo-dht or `Connect`, and one from kolo-dht or `Connect` replaces an
  attached or relayed one, so
  a pair ends on the direct path whenever one works.
- The swarm never dials a key while it holds a connection, a dial or a
  hello for it. A dial in progress is canceled when an inbound connection
  from that key is admitted; a relayed admission cancels only the relay
  dials, so a direct `Connect` still running can replace it.
- Limits: `MaxPeers` counts peers and dials together. `MaxInbound` keeps
  part of the slots for peers we chose (lookups or `Connect`), against
  eclipse attacks (Heilman et al.), and `MaxConnectPeers` caps the
  `Connect` places, whose addresses peers may supply, so at least
  `MaxPeers` - `MaxInbound` - `MaxConnectPeers` slots stay with keys
  lookups found. Each topic has the same
  split: inbound peers take at most ceil(`JoinOptions.MaxPeers` ×
  `MaxInbound` / `MaxPeers`) of its places, so peers that connect to us
  and claim a topic cannot fill it, and the topic keeps looking up and
  dialing for the rest. With a topic `MaxPeers` of 1, or `MaxInbound`
  equal to `MaxPeers`, no place is kept for dials. A peer counts in each
  topic it shares that had room when it was admitted. A connection with no
  such topic is closed with code 3, before its hello when possible.
- Hellos: a quarter of `MaxHandshakes` is kept for `Attach`, and another
  quarter for known keys: those that hold an outbound slot or had an
  outbound connection that lasted 15s. Other keys (strangers, lookup
  candidates and inbound peers included) share the rest. Below 4
  `MaxHandshakes` there is no reserve. `MaxHandshakesPerIP` bounds one
  source: an IPv4 address (as kolo-transport counts `MaxConnsPerIP`). A
  connection without a remote address counts by its relay's key if it has
  a `RelayPublicKey` method; all other such connections share one bucket.
  A hello whose window ends closes the connection with code 5, so a slow
  or silent peer holds a hello for at most about 2s, or 4s against the
  side that is not the arbiter. Peers with many addresses can still keep
  the strangers' share busy by reconnecting, but the reserves stay free
  for `Attach` and known keys.
- Backoff per key grows after a failed dial or hello or a connection
  that ended within 15s, with full jitter above a floor (see the
  table). It resets after a connection that lasted
  15s. A new address for the key ends its current wait but keeps its
  failure count. A connection closed with code 2 waits one backoff
  period, and counts as a failure unless another
  connection to the key is admitted: at once if none is in its hello,
  else when the last such hello ends without an admission. So a peer that
  answers every dial with code 2, with or without a silent extra
  connection, is dialed with growing delays. A key is retried as long as
  lookups return it.
- Dial order: keys with an outbound connection that lasted 15s go before
  all others, whatever their failures, and each group fewest failures
  first. kolo-dht opens at most 2 sessions toward an IPv4 host (any
  port), and a server can forge
  records there, so a host takes at most two dials at once: one whose
  record's `Addr` is there, and one that reaches it only through another
  address kolo-dht may probe or dial for its record (`Record.Addrs`: each
  relay's stored address). Forged relay addresses therefore never keep the
  key whose `Addr` is at a host from being dialed. kolo-dht's
  `ErrTryLater` (a punch budget here or at the peer, a relay's answer, or
  kolo-dht busy toward the host) is not a failure, but each one since the
  key's last admission grows its wait, from kolo-dht's `RandomPunchInterval`
  (20s by default) up to `RetryMax` or that interval if longer, and counts
  as a failure in the dial order until a connection to the key is
  admitted. A peer whose punched connections are full answers try later
  for as long as they last, so its key can stay in that wait with no
  `Unreachable` event.
- A key's failure count, wait and lasting-connection mark survive it
  leaving the candidates and coming back. The swarm keeps them for keys
  that are no longer candidates, up to twice `MaxCandidates`; then it keeps
  the `MaxCandidates` strongest: keys with a connection that lasted, fewest
  failures first, then other keys, most failures first, then the latest
  wait end. So a key that keeps failing is dialed with growing delays up
  to `RetryMax` however often lookups return it, unless `MaxCandidates`
  other dropped keys with as much or more to keep push it out.
- Candidates are the keys of each topic's latest lookup: per topic at
  most `MaxCandidates` divided by the number of joined topics, and
  `MaxCandidates` in all. Half of a topic's share, rounded up, is kept for
  known keys: first keys admitted now on an outbound connection, then keys
  with an outbound connection that lasted 15s, ended or not, fewest
  failures first. The rest of the share, with any place the known keys
  leave, is a uniform random sample of the lookup's other records. The
  order of the records, the age servers report and the address a record
  claims never count. A malicious server can put any address in the
  records it returns, so records that claim a peer's address lower its
  odds no more than any other records do. So a flood of fresh records
  cannot push out the known keys that fit in half of the share, a record
  gains nothing by appearing in every lookup, and a share of one place
  goes to a known key whenever the lookup returns one. A key a lookup no
  longer returns is dropped, and its backoff state is kept. `Join` and
  `Leave` cut every topic to its new share, dropping candidates without a
  slot, most failures first. When the table is full, a topic under its
  share takes a place from a topic over its share.
- Relays: `Config.Relays` is local configuration, an ordered list that
  peers of a network share like their entry nodes. kolo-dht records carry
  no relay, and a relay answers one way for a missing reservation and for
  a refusal, so a dialer cannot learn where the other side reserved.
  Therefore a swarm that announces a topic reserves at every listed relay,
  before it announces, and a dialer tries its relays one at a time: the
  one that last carried the key, then list order, skipping relays marked
  down. Two peers meet through any relay both list. No message, format or
  signature is added: "which relay" is configuration, "who dials" is the
  side whose direct dial failed (both, if both failed; the arbiter keeps
  one), and "tell the other side now" is kolo-relay's own Incoming, over
  the target's authenticated reservation connection.
- Relay dial timing: on first contact a key is dialed through the relays
  once its direct `Connect` failed with a failure (not try later, not
  denied), or once that `Connect` ran for kolo-dht's punch window of two
  consistent mappings (10 probes 1s apart plus twice `RequestTimeout`,
  12s at the defaults), past which only a random mapping can still
  connect; that `Connect` goes on and a direct connection replaces the
  relayed one. A peer behind a random mapping, which answers try later
  while its one random punch runs, does not send every candidate to the
  relays. A key whose last admitted connection was relayed, or whose last
  `Connect` failed, is dialed directly and through its relays at once.
  Relay dials are counted apart from `Connect` calls; a failed `Connect`
  that finds every relay dial busy is released as try later, with no
  `Unreachable`, since no relay was tried. A relay that fails
  without a status answer is marked down and probed once per backoff
  period; a held reservation or any status answer marks it up.
- Reservations: an end because the relay's `ReservationLifetime` passed
  (stream code 2) is not a failure, so the swarm reserves again after
  `RetryMin`; any other end and a failed `Reserve` back off, reset by a
  reservation that lasted 15s. An ended reservation is not closed: the
  sessions it carries go on, and kolo-relay closes its connection when the
  last one ends.
- The swarm does not guarantee finding or reaching every peer (kolo-dht's
  limits; NAT traversal is kolo-dht's), true topic claims (a peer can
  claim any topic we joined, since topic hashes are not secret),
  resistance to many keys from one address or many (a flood can fill the
  sampled part of every share), or fairness between topics beyond the
  per-topic limits.

## Formats

Two messages in [kolo-codec](https://github.com/ciranda-dev/kolo-codec)
encoding, on the first bidirectional stream the non-arbiter opens:

    HELLO  uvarint(version 0) ‖ uvarint(n ≤ 32) ‖ n × topic (32)
    REPLY  uvarint(version 0) ‖ uint64(epoch, little-endian) ‖ uvarint(generation) ‖ uvarint(1 ≤ n ≤ 32) ‖ n × topic (32)

The non-arbiter sends HELLO with the topic of its `Connect` dial of the
other key, if any, and the topics its lookups found that key on, then
ends the stream. The arbiter answers on the same stream with
REPLY, carrying the topics it admitted the peer for and the connection's
generation (epoch and counter), and ends it. A HELLO is at most 1026 bytes
and a REPLY at most 1044. Topics are distinct. Another version, more
topics, a duplicate, non-minimal varints or trailing bytes close the
connection with code 5.

Close codes (QUIC application error codes): 0 normal (`Close`, `Leave`),
2 duplicate or replaced, 3 full, 4 refused (`Allow` or no shared topic),
5 protocol (a malformed hello, or a hello not complete within its 2s
window or `HelloTimeout`). Code 1 is kolo-secure's and kolo-dht's. There
is no JSON form.

## References

- Heilman, Kendler, Zohar and Goldberg, [Eclipse Attacks on Bitcoin's Peer-to-Peer Network](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/heilman), USENIX Security 2015.
  Takes: connection limits against eclipse attacks.
- [RFC 8445, ICE: A Protocol for NAT Traversal](https://www.rfc-editor.org/info/rfc8445) (Proposed Standard, July 2018).
  Takes: the relayed path last.
  Not implemented: ICE itself.
- [RFC 8656, TURN: Relay Extensions to STUN](https://www.rfc-editor.org/info/rfc8656) (Proposed Standard, February 2020).
  Takes: allocation lifetimes.
  Not implemented: the TURN wire format.
- [RFC 9000, QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/info/rfc9000) (Proposed Standard, May 2021).
  Takes: application error codes (section 20.2).
- [RFC 1123, Requirements for Internet Hosts - Application and Support](https://www.rfc-editor.org/info/rfc1123) (Internet Standard, October 1989).
  Takes: the host name syntax check (section 2.1).
