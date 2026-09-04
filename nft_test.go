package main

import (
	"os"
	"testing"
)

func TestParseNFTRules(t *testing.T) {
	b, err := os.ReadFile("testdata/nft-chop_relay.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseNFT(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 3 {
		t.Fatalf("rules = %d, want 3: %+v", len(got.Rules), got.Rules)
	}
	r0 := got.Rules[0]
	if r0.Proto != "udp" || r0.Port != 2053 || r0.Origin != "203.0.113.10" || r0.OriginPort != 443 {
		t.Errorf("rule0 = %+v", r0)
	}
	if r0.NewFlows == nil || *r0.NewFlows != 126 || r0.Bytes == nil || *r0.Bytes != 54304 {
		t.Errorf("rule0 counters = %v %v", r0.NewFlows, r0.Bytes)
	}
	r1 := got.Rules[1]
	if r1.Port != 2057 || r1.OriginPort != 2407 {
		t.Errorf("rule1 = %+v (non-443 origin port must survive)", r1)
	}
	if r1.NewFlows != nil || r1.Bytes != nil {
		t.Errorf("rule1 without counter must report nil counters, got %v %v", r1.NewFlows, r1.Bytes)
	}
	r2 := got.Rules[2]
	if r2.Proto != "tcp" || r2.Port != 443 || r2.Origin != "203.0.113.30" {
		t.Errorf("rule2 = %+v", r2)
	}
}

func TestParseNFTMasquerade(t *testing.T) {
	b, _ := os.ReadFile("testdata/nft-chop_relay.json")
	got, err := ParseNFT(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Masq) != 2 {
		t.Fatalf("masq = %d, want 2", len(got.Masq))
	}
	m0 := got.Masq[0]
	if m0.Origin != "203.0.113.10" || m0.OriginPort != 443 || m0.Proto != "udp" || m0.Packets == nil || *m0.Packets != 126 {
		t.Errorf("masq0 = %+v", m0)
	}
	if got.Masq[1].Packets != nil {
		t.Errorf("masq1 has no counter, got %v", *got.Masq[1].Packets)
	}
}

func TestParseNFTEmptyTable(t *testing.T) {
	b, _ := os.ReadFile("testdata/nft-empty-table.json")
	got, err := ParseNFT(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 0 || len(got.Masq) != 0 {
		t.Errorf("expected no rules, got %+v", got)
	}
}

func TestParseNFTGarbage(t *testing.T) {
	if _, err := ParseNFT([]byte("not json")); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}
