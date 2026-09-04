package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Flow is one conntrack entry reduced to what the relay cares about.
type Flow struct {
	Proto      string
	OrigSrc    string
	OrigDst    string
	OrigSport  int
	OrigDport  int
	ReplySrc   string
	ReplySport int
	Replied    bool
}

// OriginStats is the relay->origin leg for one DNAT target.
type OriginStats struct {
	Origin     string `json:"origin"`
	OriginPort int    `json:"origin_port"`
	Proto      string `json:"proto"`
	Flows      int    `json:"flows"`
	Replied    int    `json:"replied"`
	ClientIPs  int    `json:"client_ips"`
}

// ParseConntrack accepts both `conntrack -L` lines and /proc/net/nf_conntrack
// lines. Tokens are scanned left to right; the first src/dst/sport/dport
// quadruple is the original direction, the second is the reply direction.
func ParseConntrack(text []byte) []Flow {
	var flows []Flow
	sc := bufio.NewScanner(bytes.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f, ok := parseConntrackLine(sc.Text())
		if ok {
			flows = append(flows, f)
		}
	}
	return flows
}

func parseConntrackLine(line string) (Flow, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return Flow{}, false
	}
	// procfs form starts with "ipv4 2"; strip it.
	if fields[0] == "ipv4" || fields[0] == "ipv6" {
		fields = fields[2:]
	}
	f := Flow{Proto: fields[0], Replied: true}
	seen := map[string]int{}
	for _, tok := range fields[1:] {
		if tok == "[UNREPLIED]" {
			f.Replied = false
			continue
		}
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		n := seen[k]
		seen[k] = n + 1
		switch k {
		case "src":
			if n == 0 {
				f.OrigSrc = v
			} else if n == 1 {
				f.ReplySrc = v
			}
		case "dst":
			if n == 0 {
				f.OrigDst = v
			}
		case "sport":
			p, _ := strconv.Atoi(v)
			if n == 0 {
				f.OrigSport = p
			} else if n == 1 {
				f.ReplySport = p
			}
		case "dport":
			p, _ := strconv.Atoi(v)
			if n == 0 {
				f.OrigDport = p
			}
		}
	}
	if f.OrigSrc == "" {
		return Flow{}, false
	}
	return f, true
}

// GroupByOrigin returns one OriginStats per DNAT rule, in rule order, with
// zero rows for origins that currently have no flows. A flow belongs to a
// rule when its reply source is origin:origin_port with the same proto.
func GroupByOrigin(flows []Flow, rules []Rule) []OriginStats {
	out := make([]OriginStats, 0, len(rules))
	for _, r := range rules {
		s := OriginStats{Origin: r.Origin, OriginPort: r.OriginPort, Proto: r.Proto}
		clients := map[string]struct{}{}
		for _, f := range flows {
			if f.Proto != r.Proto || f.ReplySrc != r.Origin || f.ReplySport != r.OriginPort {
				continue
			}
			s.Flows++
			if f.Replied {
				s.Replied++
			}
			clients[f.OrigSrc] = struct{}{}
		}
		s.ClientIPs = len(clients)
		out = append(out, s)
	}
	return out
}

// readConntrack prefers the procfs table when the kernel exposes it, else
// runs conntrack-tools. Returns the raw text.
func readConntrack() ([]byte, error) {
	if b, err := os.ReadFile("/proc/net/nf_conntrack"); err == nil {
		return b, nil
	}
	out, err := exec.Command("conntrack", "-L").Output()
	if err != nil {
		return nil, fmt.Errorf("conntrack: %w", err)
	}
	return out, nil
}
