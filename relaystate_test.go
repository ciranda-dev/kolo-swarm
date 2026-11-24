package koloswarm

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func TestNewRelayStateOuterLeg(t *testing.T) {
	for _, tc := range []struct {
		name string
		tc   kolotransport.Config
	}{
		{"defaults", kolotransport.Config{}},
		{"bbr and windows", kolotransport.Config{
			CongestionControl:           "bbr",
			Datagrams:                   true,
			MaxStreamReceiveWindow:      1 << 20,
			MaxConnReceiveWindow:        4 << 20,
			MaxConns:                    300,
			MaxConnsPerIP:               7,
			MaxDialed:                   300,
			MaxMemory:                   4 << 30,
			WindowGrowth:                true,
			MaxGrownStreamReceiveWindow: 8 << 20,
			MaxGrownConnReceiveWindow:   16 << 20,
			MaxGrownMemory:              1 << 30,
			AcceptFunc:                  func(netip.AddrPort) bool { return true },
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sec := &kolosecure.Config{Transport: &tc.tc}
			s := &Swarm{cfg: Config{DHT: &kolodht.Config{Secure: sec}}}
			cfg := newRelayState(s, Relay{}).cfg
			if cfg.Relay == nil || cfg.Relay.Transport == nil {
				t.Fatal("no relay leg config")
			}
			got := *cfg.Relay.Transport
			want := kolotransport.Config{
				CongestionControl:      tc.tc.CongestionControl,
				MaxStreamReceiveWindow: tc.tc.MaxStreamReceiveWindow,
				MaxConnReceiveWindow:   tc.tc.MaxConnReceiveWindow,
				KeepAlivePeriod:        5 * time.Second,
				Datagrams:              tc.tc.Datagrams,
			}
			if got.CongestionControl != want.CongestionControl || got.MaxStreamReceiveWindow != want.MaxStreamReceiveWindow ||
				got.MaxConnReceiveWindow != want.MaxConnReceiveWindow || got.KeepAlivePeriod != want.KeepAlivePeriod || got.Datagrams != want.Datagrams {
				t.Fatalf("relay leg %+v, want %+v", got, want)
			}
			got.CongestionControl, got.MaxStreamReceiveWindow, got.MaxConnReceiveWindow, got.KeepAlivePeriod, got.Datagrams = "", 0, 0, 0, false
			if !reflect.DeepEqual(got, kolotransport.Config{}) {
				t.Fatalf("relay leg copies listener or growth fields: %+v", got)
			}
			if cfg.Relay.Transport == &tc.tc || cfg.Peer.Transport == cfg.Relay.Transport {
				t.Fatal("the relay leg shares a config with the swarm or the peer leg")
			}
			if pt := cfg.Peer.Transport; pt.CongestionControl != tc.tc.CongestionControl || pt.MaxConnReceiveWindow != tc.tc.MaxConnReceiveWindow || pt.MaxDialed != tc.tc.MaxDialed {
				t.Fatalf("peer leg %+v", pt)
			}
		})
	}
}
