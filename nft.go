package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// Rule is one DNAT entry in the prerouting chain.
type Rule struct {
	Proto      string  `json:"proto"`
	Port       int     `json:"port"`
	Origin     string  `json:"origin"`
	OriginPort int     `json:"origin_port"`
	NewFlows   *uint64 `json:"new_flows"` // nat-hook counter = first packet per flow
	Bytes      *uint64 `json:"bytes"`
}

// Masq is one masquerade entry in the postrouting chain.
type Masq struct {
	Proto      string  `json:"proto"`
	Origin     string  `json:"origin"`
	OriginPort int     `json:"origin_port"`
	Packets    *uint64 `json:"packets"`
	Bytes      *uint64 `json:"bytes"`
}

// NFTRules is the parsed content of one nft table.
type NFTRules struct {
	Rules []Rule `json:"rules"`
	Masq  []Masq `json:"masquerade"`
}

// nftDoc mirrors the parts of `nft -j` output we read.
type nftDoc struct {
	Nftables []struct {
		Rule *struct {
			Chain string            `json:"chain"`
			Expr  []json.RawMessage `json:"expr"`
		} `json:"rule"`
	} `json:"nftables"`
}

type nftMatch struct {
	Left struct {
		Meta    *struct{ Key string `json:"key"` } `json:"meta"`
		Payload *struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		} `json:"payload"`
	} `json:"left"`
	Right json.RawMessage `json:"right"`
}

type nftDnat struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
}

type nftExpr struct {
	Match   *nftMatch `json:"match"`
	Counter *struct {
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
	} `json:"counter"`
	Dnat       *nftDnat        `json:"dnat"`
	Masquerade json.RawMessage `json:"masquerade"`
}

// ParseNFT turns `nft -j list table ip <table>` output into NFTRules.
// Rules with set/range matches (not a single int/string) are skipped.
func ParseNFT(jsonOut []byte) (NFTRules, error) {
	var doc nftDoc
	if err := json.Unmarshal(jsonOut, &doc); err != nil {
		return NFTRules{}, fmt.Errorf("nft json: %w", err)
	}
	out := NFTRules{Rules: []Rule{}, Masq: []Masq{}}
	for _, item := range doc.Nftables {
		if item.Rule == nil {
			continue
		}
		var proto, daddr string
		var dport int
		var pkts, bytes *uint64
		var dnat *nftDnat
		isMasq := false
		for _, raw := range item.Rule.Expr {
			var e nftExpr
			if err := json.Unmarshal(raw, &e); err != nil {
				continue
			}
			switch {
			case e.Match != nil && e.Match.Left.Payload != nil:
				p := e.Match.Left.Payload
				switch p.Field {
				case "dport":
					var v int
					if json.Unmarshal(e.Match.Right, &v) == nil {
						proto, dport = p.Protocol, v
					}
				case "daddr":
					var v string
					if json.Unmarshal(e.Match.Right, &v) == nil {
						daddr = v
					}
				}
			case e.Counter != nil:
				p, b := e.Counter.Packets, e.Counter.Bytes
				pkts, bytes = &p, &b
			case e.Dnat != nil:
				dnat = e.Dnat
			case len(e.Masquerade) > 0:
				isMasq = true
			}
		}
		switch {
		case dnat != nil && dport != 0:
			out.Rules = append(out.Rules, Rule{
				Proto: proto, Port: dport, Origin: dnat.Addr, OriginPort: dnat.Port,
				NewFlows: pkts, Bytes: bytes,
			})
		case isMasq && daddr != "":
			out.Masq = append(out.Masq, Masq{
				Proto: proto, Origin: daddr, OriginPort: dport, Packets: pkts, Bytes: bytes,
			})
		}
	}
	return out, nil
}

// runNFT executes nft and returns its JSON. Callers treat an error as
// "table absent or nft missing", not as a request failure.
func runNFT(table string) ([]byte, error) {
	out, err := exec.Command("nft", "-j", "list", "table", "ip", table).Output()
	if err != nil {
		return nil, fmt.Errorf("nft: %w", err)
	}
	return out, nil
}
