package koloswarm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-swarm/internal/events"
)

// Close codes sent to the peer (QUIC application error codes); 1 belongs to kolo-secure and kolo-dht.
const (
	codeNormal    = 0
	codeDuplicate = 2
	codeFull      = 3
	codeRefused   = 4
	codeProtocol  = 5
)

const (
	lasting     = 15 * time.Second // a connection this old resets its key's failure count
	helloPerKey = 2
	quickHello  = 2 * time.Second // the window for each part of the hello
	minWait     = 10 * time.Millisecond
)

// Queue classes: Found and Unreachable each have their own MaxEvents budget, and RelayChanged one per listed relay.
const (
	classFound = 1 + iota
	classUnreachable
	classRelay
)

type key = [ed25519.PublicKeySize]byte

// slot is one remote key's place in MaxPeers: a dial in progress, a connected peer, or both.
type slot struct {
	inbound  bool
	topic    Topic        // the topic a dial reserved it for
	own      netip.Addr   // the IPv4 host of the dialed record's Addr
	via      []netip.Addr // the other IPv4 hosts kolo-dht may probe for it, from relays
	dial     context.CancelFunc
	peer     *Peer
	connect  bool // taken by Swarm.Connect
	reserved bool // the Swarm.Connect that took it still runs, so a lost peer leaves the place to it

	// With Config.Relays only.
	rdial    context.CancelFunc // cancels the relay chain
	settled  bool               // the direct Connect returned, so the slot no longer holds a kolo-dht session
	relaying bool               // a relay chain was started for this slot
	paths    int                // dial paths not finished yet
	why      int                // the release reason of the paths finished so far
	unreach  bool               // the direct Connect returned kolodht.ErrUnreachable
}

type topicState struct {
	opts      JoinOptions
	ctx       context.Context
	cancel    context.CancelFunc
	joining   bool
	left      bool
	announced bool
}

// JoinOptions says how to join a topic. Announce publishes our record; Lookup finds and dials others.
type JoinOptions struct {
	// Announce publishes our record on the topic.
	Announce bool
	// Lookup finds the other peers of the topic and dials them.
	Lookup bool
	// MaxPeers caps the peers dialed or admitted for this topic. Default and maximum: Config.MaxPeers.
	MaxPeers int
}

// Swarm keeps connections to the peers of the topics it joined, on its own kolo-dht node.
type Swarm struct {
	key      ed25519.PublicKey
	self     key
	id       *koloid.Identity
	relays   []*relayState // nil without Config.Relays
	node     *kolodht.Node
	cfg      Config
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	once     sync.Once
	closeErr error
	events   *events.Queue[Event]
	wake     chan struct{}

	mu            sync.Mutex
	closed        bool
	topics        map[Topic]*topicState
	slots         map[key]*slot
	inbound       int
	hellos        int
	strangers     int
	attaching     int
	helloKey      map[key]int
	helloSrc      map[string]int
	cands         map[key]*cand
	past          map[key]*history // keys that are no longer candidates, at most MaxCandidates
	dialing       int
	dials         map[pair]*connectDial       // Swarm.Connect dials whose key has not proved itself yet
	endFails      map[netip.AddrPort]*failure // Swarm.Connect backoff per address, at most twice MaxCandidates
	pairFails     map[pair]*failure           // Swarm.Connect backoff per key and address, at most twice MaxCandidates
	hostFloor     map[netip.Addr]time.Time    // Swarm.Connect wait per host after a failed dial, at most twice MaxCandidates
	connectTokens float64                     // Swarm.Connect dial starts left
	connectFill   time.Time                   // when connectTokens was last refilled
	relayed       int                         // relay chains in progress
	gen           generation                  // the next one the arbiter gives
	hooks         testHooks
}

// New opens a kolo-dht node on addr, such as "127.0.0.1:0" or ":4000", as id, and starts the swarm on it.
// kolo-swarm is IPv4 only: an IPv6 addr, IPv4-mapped included, is ErrInvalidArgument.
func New(ctx context.Context, addr string, id *koloid.Identity, cfg *Config) (*Swarm, error) {
	pub := id.PublicKey()
	if pub == nil {
		return nil, fmt.Errorf("%w: nil or zero identity", ErrInvalidArgument)
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil && !ip.Is4() {
			return nil, errIPv6("listen address")
		}
	}
	c, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		// The caller's list, since c.Relays has no duplicates and so other positions.
		for i, r := range cfg.Relays {
			if bytes.Equal(r.PublicKey, pub) {
				return nil, fmt.Errorf("%w: Relays: entry %d: our own key", ErrInvalidConfig, i+1)
			}
		}
	}
	node, err := kolodht.New(ctx, addr, id, c.DHT)
	if err != nil {
		if errors.Is(err, kolodht.ErrInvalidConfig) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		return nil, err
	}
	sctx, cancel := context.WithCancel(context.Background())
	s := &Swarm{
		key:       bytes.Clone(pub),
		self:      key(pub),
		id:        id,
		node:      node,
		cfg:       c,
		ctx:       sctx,
		cancel:    cancel,
		events:    events.New[Event](c.MaxEvents, c.MaxEvents, len(c.Relays)),
		wake:      make(chan struct{}, 1),
		topics:    make(map[Topic]*topicState),
		slots:     make(map[key]*slot),
		helloKey:  make(map[key]int),
		helloSrc:  make(map[string]int),
		cands:     make(map[key]*cand),
		past:      make(map[key]*history),
		dials:     make(map[pair]*connectDial),
		endFails:  make(map[netip.AddrPort]*failure),
		pairFails: make(map[pair]*failure),
		hostFloor: make(map[netip.Addr]time.Time),
		gen:       generation{epoch: rand.Uint64(), n: 1},
	}
	for _, r := range c.Relays {
		s.relays = append(s.relays, newRelayState(s, r))
	}
	s.mu.Lock()
	s.spawnLocked(s.acceptLoop)
	s.spawnLocked(s.dialLoop)
	s.mu.Unlock()
	return s, nil
}

// Addr returns the local address of the node's UDP socket.
func (s *Swarm) Addr() net.Addr { return s.node.Addr() }

// PublicKey returns a copy of the swarm's kolo-id public key.
func (s *Swarm) PublicKey() ed25519.PublicKey { return bytes.Clone(s.key) }

// Bootstrap passes servers to kolo-dht Bootstrap; its ErrNoNodes passes through, and its ErrInvalidArgument is wrapped
// in ours. An IPv6 server address, IPv4-mapped included, is ErrInvalidArgument. With no servers it resolves
// Config.BootstrapNodes instead (ErrNoNodes if none resolves), each name within 5s and ctx.
//
// With neither, a nil servers list joins the public network: Ciranda's entry nodes built into kolo-dht learn this
// node's IP address and public key, and Join with Announce publishes the topic hash and IP address there. A nil slice
// from a flag or an empty parse counts as nil. To stay private, pass your own non-empty list or set
// Config.BootstrapNodes; an empty list that is not nil is ErrInvalidArgument and sends nothing.
func (s *Swarm) Bootstrap(ctx context.Context, servers []netip.AddrPort) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.ctx.Err() != nil {
		return ErrClosed
	}
	if len(servers) == 0 && len(s.cfg.BootstrapNodes) > 0 {
		var err error
		if servers, err = resolveNodes(ctx, s.cfg.BootstrapNodes, s.localIP()); err != nil {
			return err
		}
	}
	err := s.node.Bootstrap(ctx, servers)
	switch {
	case errors.Is(err, kolodht.ErrClosed):
		return ErrClosed
	case errors.Is(err, kolodht.ErrInvalidArgument):
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return err
}

// localIP returns the IPv4 host of the node's socket, or the zero Addr.
func (s *Swarm) localIP() netip.Addr {
	if ua, ok := s.node.Addr().(*net.UDPAddr); ok {
		return ua.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

func errIPv6(what string) error {
	return fmt.Errorf("%w: IPv6 %s, and kolo-swarm is IPv4 only", ErrInvalidArgument, what)
}

// Close closes every peer connection and the node, and waits for the swarm's goroutines. It is safe to call more than once.
func (s *Swarm) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		var conns []Conn
		for _, sl := range s.slots {
			if sl.peer != nil {
				conns = append(conns, sl.peer.conn)
			}
		}
		for _, t := range s.topics {
			t.cancel()
		}
		s.mu.Unlock()
		s.cancel()
		s.closeAll(conns)
		s.closeErr = s.node.Close()
		s.wg.Wait()
	})
	return s.closeErr
}

// spawnLocked runs f in a goroutine that Close waits for, unless closed. Call with mu held.
func (s *Swarm) spawnLocked(f func()) bool {
	if s.closed {
		return false
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		f()
	}()
	return true
}

func (s *Swarm) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Next returns the next event. Connected and Lost are never dropped; Found and Unreachable are dropped past MaxEvents.
// A peer can be replaced by a newer connection to the same key: its Lost, with ErrDuplicate, comes before the new Connected.
func (s *Swarm) Next(ctx context.Context) (Event, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Event{}, err
		}
		if s.ctx.Err() != nil {
			return Event{}, ErrClosed
		}
		ev, err := s.events.Pop(ctx, s.ctx.Done())
		if err != nil {
			if errors.Is(err, events.ErrDone) {
				return Event{}, ErrClosed
			}
			return Event{}, err
		}
		if ev.Kind == Connected {
			s.mu.Lock()
			gone := ev.Peer.gone
			ev.Peer.delivered = !gone
			s.mu.Unlock()
			if gone {
				continue
			}
		}
		return ev, nil
	}
}

// Join announces topic, looks it up, or both (nil opts), and connects to the peers found. With Announce it returns
// once kolo-dht stored our record, and its errors pass through; the topic is then not joined. Lookups run every
// LookupInterval in the background. If Leave(topic) runs during Join, Join returns context.Canceled. With Announce
// and Config.Relays, it first waits for the first reservation attempt at each relay, in parallel, except relays known
// down.
func (s *Swarm) Join(ctx context.Context, topic Topic, opts *JoinOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	o := JoinOptions{Announce: true, Lookup: true}
	if opts != nil {
		o = *opts
	}
	switch {
	case !o.Announce && !o.Lookup:
		return fmt.Errorf("%w: JoinOptions needs Announce or Lookup", ErrInvalidArgument)
	case o.MaxPeers == 0:
		o.MaxPeers = s.cfg.MaxPeers
	case o.MaxPeers < 1 || o.MaxPeers > s.cfg.MaxPeers:
		return fmt.Errorf("%w: JoinOptions.MaxPeers must be between 1 and MaxPeers", ErrInvalidArgument)
	}
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		return ErrClosed
	case s.topics[topic] != nil:
		s.mu.Unlock()
		return fmt.Errorf("%w: topic already joined", ErrInvalidArgument)
	case len(s.topics) >= s.cfg.MaxTopics:
		s.mu.Unlock()
		return fmt.Errorf("%w: MaxTopics reached", ErrInvalidArgument)
	}
	tctx, cancel := context.WithCancel(s.ctx)
	t := &topicState{opts: o, ctx: tctx, cancel: cancel, joining: true}
	s.topics[topic] = t
	s.trimLocked()
	var reserved []<-chan struct{}
	if o.Announce {
		for _, r := range s.relays {
			if ch := s.relayStartLocked(r); ch != nil {
				reserved = append(reserved, ch)
			}
		}
	}
	s.mu.Unlock()

	var err error
	if o.Announce {
		actx, stop := mergeCtx(ctx, tctx)
		for _, ch := range reserved {
			select {
			case <-ch:
			case <-actx.Done():
			}
		}
		err = s.node.Announce(actx, topic)
		stop()
	}
	s.mu.Lock()
	if err == nil && !t.left && !s.closed {
		t.joining = false
		t.announced = o.Announce
		if o.Lookup {
			s.spawnLocked(func() { s.lookupLoop(topic, t) })
		}
		s.mu.Unlock()
		return nil
	}
	left := t.left
	if s.topics[topic] == t {
		delete(s.topics, topic)
	}
	for _, r := range s.relays {
		s.relayStopLocked(r)
	}
	s.mu.Unlock()
	cancel()
	if err == nil && o.Announce {
		s.node.Unannounce(topic)
	}
	switch {
	case s.ctx.Err() != nil:
		return ErrClosed
	case ctx.Err() != nil:
		return ctx.Err()
	case left:
		return context.Canceled
	case errors.Is(err, kolodht.ErrClosed):
		return ErrClosed
	}
	return err
}

// mergeCtx returns a context canceled when a or b is.
func mergeCtx(a, b context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(a)
	stop := context.AfterFunc(b, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// Leave stops announcing and looking up topic, and closes the peers that share no other topic with us; with
// Config.Relays, those closes may finish after it returns.
func (s *Swarm) Leave(topic Topic) {
	s.mu.Lock()
	t := s.topics[topic]
	if t == nil || t.left {
		s.mu.Unlock()
		return
	}
	t.left = true
	t.cancel()
	if t.joining {
		s.mu.Unlock()
		return
	}
	delete(s.topics, topic)
	announced := t.announced
	for k, c := range s.cands {
		s.dropCandTopicLocked(k, c, topic)
	}
	var drop []Conn
	for _, d := range s.dials {
		if d.topic == topic {
			d.cancel()
		}
	}
	for _, sl := range s.slots {
		if sl.peer == nil && sl.topic == topic && sl.dial != nil {
			sl.dial()
		}
		if sl.peer == nil && sl.topic == topic && sl.rdial != nil {
			sl.rdial()
		}
		if p := sl.peer; p != nil && slices.Contains(p.topics, topic) {
			p.topics = slices.DeleteFunc(p.topics, func(x Topic) bool { return x == topic })
			if len(p.topics) == 0 {
				drop = append(drop, p.conn)
			}
		}
	}
	s.trimLocked()
	for _, r := range s.relays {
		s.relayStopLocked(r)
	}
	s.mu.Unlock()
	if announced {
		s.node.Unannounce(topic)
	}
	for _, c := range drop {
		if s.relays == nil {
			c.CloseWithError(codeNormal, "")
		} else {
			s.closeAsync(c, codeNormal)
		}
	}
}

// closeAll closes conns with code 0; with Config.Relays in parallel, since a relayed close can take seconds.
func (s *Swarm) closeAll(conns []Conn) {
	if s.relays == nil {
		for _, c := range conns {
			c.CloseWithError(codeNormal, "")
		}
		return
	}
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Go(func() { c.CloseWithError(codeNormal, "") })
	}
	wg.Wait()
}

// closeAsync closes c in a goroutine that Close waits for.
func (s *Swarm) closeAsync(c Conn, code uint64) {
	s.mu.Lock()
	ok := s.spawnLocked(func() { c.CloseWithError(code, "") })
	s.mu.Unlock()
	if !ok {
		c.CloseWithError(code, "")
	}
}

func (s *Swarm) joinedLocked(topic Topic) bool {
	t := s.topics[topic]
	return t != nil && !t.left
}

// placesLocked counts the places in MaxPeers: slots and Connect dials not proved yet. Call with mu held.
func (s *Swarm) placesLocked() int { return len(s.slots) + len(s.dials) }

// countsLocked returns the peers and dials of topic, and the inbound peers among them. Call with mu held.
func (s *Swarm) countsLocked(topic Topic) (total, inbound int) {
	for _, d := range s.dials {
		if d.topic == topic {
			total++
		}
	}
	for _, sl := range s.slots {
		switch {
		case sl.peer != nil && slices.Contains(sl.peer.topics, topic):
			total++
			if sl.inbound {
				inbound++
			}
		case sl.peer == nil && sl.topic == topic:
			total++
		}
	}
	return total, inbound
}

// inboundCap is the inbound share of a topic's limit, MaxInbound/MaxPeers of it rounded up.
func (s *Swarm) inboundCap(t *topicState) int {
	return max(1, (t.opts.MaxPeers*s.cfg.MaxInbound+s.cfg.MaxPeers-1)/s.cfg.MaxPeers)
}

// roomLocked reports whether topic x has room for one more peer. Call with mu held.
func (s *Swarm) roomLocked(x Topic, inbound bool) bool {
	t := s.topics[x]
	if t == nil || t.left {
		return false
	}
	total, in := s.countsLocked(x)
	return total < t.opts.MaxPeers && (!inbound || in < s.inboundCap(t))
}

// fitLocked returns the joined topics with room for a connection on slot sl (nil if new), keeping those sl already
// holds; joined reports whether any of topics is joined. Call with mu held.
func (s *Swarm) fitLocked(topics []Topic, inbound bool, sl *slot) (kept []Topic, joined bool) {
	for _, x := range topics {
		if !s.joinedLocked(x) {
			continue
		}
		joined = true
		held := sl != nil && ((sl.peer != nil && slices.Contains(sl.peer.topics, x)) || (sl.peer == nil && sl.topic == x))
		if held || s.roomLocked(x, inbound) {
			kept = append(kept, x)
		}
	}
	return kept, joined
}
