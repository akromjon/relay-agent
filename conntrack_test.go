package main

import (
	"os"
	"testing"
)

func TestParseConntrack(t *testing.T) {
	b, err := os.ReadFile("testdata/conntrack-L.txt")
	if err != nil {
		t.Fatal(err)
	}
	flows := ParseConntrack(b)
	if len(flows) != 7 {
		t.Fatalf("flows = %d, want 7", len(flows))
	}
	f := flows[0]
	if f.Proto != "udp" || f.OrigSrc != "198.51.100.11" || f.OrigDport != 2053 || f.ReplySrc != "203.0.113.10" || f.ReplySport != 443 || !f.Replied {
		t.Errorf("flow0 = %+v", f)
	}
	if flows[3].Replied {
		t.Error("flow3 is [UNREPLIED] and must parse as Replied=false")
	}
	if flows[5].Proto != "tcp" || flows[5].OrigDport != 22 {
		t.Errorf("tcp line with state column parsed wrong: %+v", flows[5])
	}
}

func TestParseConntrackProcfsPrefix(t *testing.T) {
	// /proc/net/nf_conntrack prefixes "ipv4     2 " before the proto.
	line := []byte("ipv4     2 udp      17 29 src=198.51.100.11 dst=192.0.2.1 sport=1 dport=2053 src=203.0.113.10 dst=192.0.2.1 sport=443 dport=1 [ASSURED] mark=0 use=1\n")
	flows := ParseConntrack(line)
	if len(flows) != 1 || flows[0].Proto != "udp" || flows[0].ReplySport != 443 {
		t.Errorf("got %+v", flows)
	}
}

func TestGroupByOrigin(t *testing.T) {
	b, _ := os.ReadFile("testdata/conntrack-L.txt")
	flows := ParseConntrack(b)
	rules := []Rule{
		{Proto: "udp", Port: 2053, Origin: "203.0.113.10", OriginPort: 443},
		{Proto: "udp", Port: 2057, Origin: "203.0.113.20", OriginPort: 2407},
		{Proto: "udp", Port: 2058, Origin: "203.0.113.40", OriginPort: 443}, // no flows
	}
	got := GroupByOrigin(flows, rules)
	if len(got) != 3 {
		t.Fatalf("groups = %d, want 3 (one per rule, zeroes included): %+v", len(got), got)
	}
	g := got[0]
	if g.Origin != "203.0.113.10" || g.Flows != 4 || g.Replied != 3 || g.ClientIPs != 3 {
		t.Errorf("origin .10 = %+v", g)
	}
	if got[1].Flows != 1 || got[1].Replied != 1 || got[1].OriginPort != 2407 {
		t.Errorf("origin .20 = %+v", got[1])
	}
	if got[2].Flows != 0 || got[2].Replied != 0 || got[2].ClientIPs != 0 {
		t.Errorf("origin .40 = %+v (must be zero row)", got[2])
	}
}
