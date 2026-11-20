package koloswarm

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
)

func hasKey(recs []kolodht.Record, key ed25519.PublicKey) bool {
	for _, r := range recs {
		if bytes.Equal(r.PublicKey, key) {
			return true
		}
	}
	return false
}

// TestLookupOnlyNotAnnounced checks that a lookup-only swarm stores no record, while an announcing one on the same
// topic does.
func TestLookupOnlyNotAnnounced(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	client, server, other := newSwarm(t, srv, nil, nil), newSwarm(t, srv, nil, nil), newSwarm(t, srv, nil, nil)
	wc := watch(t, client)
	topic := topicOf("lookup only")
	join(t, server, topic, &JoinOptions{Announce: true})
	join(t, client, topic, &JoinOptions{Lookup: true})
	waitFor(t, 15*time.Second, "client connected", func() bool { return wc.peer(server.PublicKey()) != nil })
	recs, err := other.node.Lookup(testCtx(t, 10*time.Second), topic)
	if err != nil {
		t.Fatal(err)
	}
	if !hasKey(recs, server.PublicKey()) {
		t.Fatal("announcing swarm missing from Lookup")
	}
	if hasKey(recs, client.PublicKey()) {
		t.Fatal("lookup-only swarm found by Lookup")
	}
}

// TestAnnounceOnlyNoLookup checks that two announce-only swarms on one topic, each findable by the other's Lookup,
// never find or connect to each other.
func TestAnnounceOnlyNoLookup(t *testing.T) {
	checkGoroutines(t)
	srv := newServer(t)
	a, b := newSwarm(t, srv, nil, nil), newSwarm(t, srv, nil, nil)
	wa, wb := watch(t, a), watch(t, b)
	topic := topicOf("announce only")
	join(t, a, topic, &JoinOptions{Announce: true})
	join(t, b, topic, &JoinOptions{Announce: true})
	ctx := testCtx(t, 10*time.Second)
	for _, x := range []struct{ s, peer *Swarm }{{a, b}, {b, a}} {
		recs, err := x.s.node.Lookup(ctx, topic)
		if err != nil {
			t.Fatal(err)
		}
		if !hasKey(recs, x.peer.PublicKey()) {
			t.Fatal("announced record missing from Lookup")
		}
	}
	// fastConfig looks up every second, so a lookup would find the other within this window.
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		for _, w := range []*watcher{wa, wb} {
			if n := w.kinds(Found) + w.kinds(Connected); n > 0 {
				w.dump(t, "swarm")
				t.Fatalf("announce-only swarm reported %d Found or Connected events", n)
			}
		}
	}
}
