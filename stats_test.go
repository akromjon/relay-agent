package main

import (
	"errors"
	"os"
	"testing"
	"time"
)

func fakeSources(t *testing.T, nftErr, ctErr error) Sources {
	t.Helper()
	read := func(name string) []byte { b, _ := os.ReadFile("testdata/" + name); return b }
	statCalls := 0
	return Sources{
		NFT: func(table string) ([]byte, error) {
			if nftErr != nil {
				return nil, nftErr
			}
			return read("nft-chop_relay.json"), nil
		},
		Conntrack: func() ([]byte, error) {
			if ctErr != nil {
				return nil, ctErr
			}
			return read("conntrack-L.txt"), nil
		},
		ReadFile: func(path string) ([]byte, error) {
			switch path {
			case "/proc/net/route":
				return read("proc-net-route.txt"), nil
			case "/proc/net/dev":
				return read("proc-net-dev.txt"), nil
			case "/proc/loadavg":
				return []byte("0.02 0.05 0.01 1/123 4567\n"), nil
			case "/proc/meminfo":
				return read("proc-meminfo.txt"), nil
			case "/proc/stat":
				statCalls++
				if statCalls == 1 {
					return read("proc-stat-a.txt"), nil
				}
				return read("proc-stat-b.txt"), nil
			case "/proc/sys/net/netfilter/nf_conntrack_count":
				return []byte("6\n"), nil
			case "/proc/sys/net/netfilter/nf_conntrack_max":
				return []byte("262144\n"), nil
			case "/proc/sys/net/ipv4/ip_forward":
				return []byte("1\n"), nil
			}
			return nil, os.ErrNotExist
		},
		Sleep: func(time.Duration) {},
		Now:   func() time.Time { return time.Unix(1757000000, 0) },
	}
}

func TestCollectorStatsHappyPath(t *testing.T) {
	c := &Collector{Settings: Settings{NFTTable: "chop_relay"}, Src: fakeSources(t, nil, nil), Version: "test", Started: time.Unix(1756999000, 0)}
	s, err := c.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.TS != 1757000000 || s.Iface != "eth0" {
		t.Errorf("ts/iface = %d %q", s.TS, s.Iface)
	}
	if len(s.Rules) != 3 || len(s.Origins) != 3 {
		t.Errorf("rules=%d origins=%d", len(s.Rules), len(s.Origins))
	}
	if s.Origins[0].Flows != 4 || s.Origins[0].Replied != 3 {
		t.Errorf("origin0 = %+v", s.Origins[0])
	}
	b := s.Box
	if b.RxBytes != 4315119032 || b.RxDrop != 13 || b.Load1 != 0.02 || b.MemAvailKB != 690000 {
		t.Errorf("box = %+v", b)
	}
	if b.ConntrackCount == nil || *b.ConntrackCount != 6 || b.ConntrackMax == nil || *b.ConntrackMax != 262144 {
		t.Errorf("conntrack = %v %v", b.ConntrackCount, b.ConntrackMax)
	}
	if b.CPUStealPct < 4.99 || b.CPUStealPct > 5.01 || b.CPUIdlePct < 89.99 || b.CPUIdlePct > 90.01 {
		t.Errorf("cpu = %v/%v", b.CPUIdlePct, b.CPUStealPct)
	}
	if len(s.Warnings) != 0 {
		t.Errorf("unexpected warnings %v", s.Warnings)
	}
}

func TestCollectorStatsDegrades(t *testing.T) {
	c := &Collector{Settings: Settings{NFTTable: "chop_relay"}, Src: fakeSources(t, errors.New("nft: exit 1"), errors.New("conntrack: not found")), Version: "test", Started: time.Now()}
	s, err := c.Stats()
	if err != nil {
		t.Fatalf("missing tools must not fail the request: %v", err)
	}
	if len(s.Rules) != 0 || len(s.Origins) != 0 {
		t.Errorf("expected empty rules/origins, got %+v", s)
	}
	if len(s.Warnings) != 2 {
		t.Errorf("expected 2 warnings, got %v", s.Warnings)
	}
}

func TestCollectorStatsIfaceOverride(t *testing.T) {
	c := &Collector{Settings: Settings{NFTTable: "chop_relay", Iface: "lo"}, Src: fakeSources(t, nil, nil), Version: "test", Started: time.Now()}
	s, err := c.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.Iface != "lo" || s.Box.RxBytes != 1234567 {
		t.Errorf("iface override ignored: %q %d", s.Iface, s.Box.RxBytes)
	}
}

func TestCollectorHealth(t *testing.T) {
	c := &Collector{Settings: Settings{NFTTable: "chop_relay"}, Src: fakeSources(t, nil, nil), Version: "0.1.0", Started: time.Unix(1756999000, 0)}
	h := c.Health()
	if !h.Running || h.Version != "0.1.0" || h.UptimeS != 1000 || h.Iface != "eth0" {
		t.Errorf("health = %+v", h)
	}
	if h.IPForward == nil || !*h.IPForward || h.ConntrackMax == nil || *h.ConntrackMax != 262144 || !h.NFTTablePresent {
		t.Errorf("health = %+v", h)
	}
	c.Src = fakeSources(t, errors.New("no table"), nil)
	if c.Health().NFTTablePresent {
		t.Error("NFTTablePresent must be false when nft fails")
	}
}
