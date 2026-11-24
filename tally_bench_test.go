package koloswarm

import (
	"fmt"
	"testing"
)

// benchSwarm holds the 1258 default places, each on perPeer of the topics joined, for the calls made under mu.
func benchSwarm(b *testing.B, topics, perPeer int) (*Swarm, []Topic) {
	b.Helper()
	xs := make([]Topic, topics)
	for i := range xs {
		xs[i] = topicOf(fmt.Sprint("bench", i))
	}
	cfg, err := (*Config)(nil).withDefaults()
	if err != nil {
		b.Fatal(err)
	}
	s := &Swarm{cfg: cfg, topics: map[Topic]*topicState{}, slots: map[key]*slot{}}
	for _, x := range xs {
		joinUnit(s, x, 0)
	}
	for i := range s.cfg.MaxPeers {
		var k key
		k[0], k[1] = byte(i), byte(i>>8)
		own := make([]Topic, perPeer)
		for j := range own {
			own[j] = xs[(i+j)%topics]
		}
		s.slots[k] = &slot{inbound: i%2 == 0, peer: &Peer{topics: own}}
	}
	return s, xs
}

func BenchmarkTally(b *testing.B) {
	for _, c := range []struct{ topics, perPeer int }{{1, 1}, {50, 8}, {64, 32}, {64, 64}} {
		b.Run(fmt.Sprintf("topics=%d/perPeer=%d", c.topics, c.perPeer), func(b *testing.B) {
			s, xs := benchSwarm(b, c.topics, c.perPeer)
			b.Run("tally", func(b *testing.B) {
				for range b.N {
					s.mu.Lock()
					s.tallyLocked()
					s.mu.Unlock()
				}
			})
			b.Run("room", func(b *testing.B) {
				for i := range b.N {
					s.mu.Lock()
					s.roomLocked(xs[i%len(xs)], true)
					s.mu.Unlock()
				}
			})
		})
	}
}
