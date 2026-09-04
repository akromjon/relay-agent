# relay-agent Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A read-only, stdlib-only Go HTTP agent that reports nftables DNAT counters, conntrack reply state and box counters from a CHOP relay box, plus the installer that preps a bare VPS and runs it under systemd.

**Architecture:** One static binary. `settings.go` reads env; `server.go` serves three authenticated JSON endpoints; `stats.go` assembles a `Stats` value from three pure parsers (`nft.go`, `conntrack.go`, `procstats.go`) that take `[]byte` and are tested against fixtures in `testdata/`. Command execution and file reads are injected through small function types so every parser runs on the dev Mac without root, nftables or Linux.

**Tech Stack:** Go 1.22, standard library only (`net/http`, `encoding/json`, `os/exec`, `crypto/subtle`, `testing`). Bash for `build.sh` / `install.sh`. systemd unit.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-04-relay-agent-design.md`. Read it first.
- **No third-party Go modules.** `go.mod` must have no `require` block.
- **Read-only.** Phase 1 never writes nft rules, files under `/etc`, or sysctls. Only the installer writes, and only during install.
- Auth: header `key: <API_TOKEN>`; wrong or missing key → HTTP **404** (never 401/403).
- Default listen `0.0.0.0:8080`, env `RELAY_AGENT_PORT` overrides.
- Build: `CGO_ENABLED=0 GOOS=linux`, both `amd64` and `arm64`, `-ldflags="-s -w -X main.version=<tag>"`, `.sha256` beside each binary.
- systemd ceilings: `MemoryMax=32M`, `CPUQuota=10%`, `CapabilityBoundingSet=CAP_NET_ADMIN`.
- Parsers must tolerate missing tools: absent nft table → `rules: []`, absent conntrack → `origins: []` + warning. Never crash the request on a missing tool.
- `install.sh` must **never** rewrite an `/etc/nftables.conf` that already contains `chop_relay`.
- Fixture IPs use documentation ranges (`198.51.100.0/24` clients, `203.0.113.0/24` origins, `192.0.2.0/24` relay). Never commit real client addresses.
- Commit after every task; commit messages in plain imperative style, no scope prefixes required beyond `feat:` / `test:` / `docs:` / `build:`.
- Every command below runs from the repo root `/Users/admin/mobile-app/ultimate-vpn-app/relay-agent` unless stated.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `go.mod` | module `github.com/akromjon/relay-agent`, `go 1.22`, no requires |
| `main.go` | wire settings → collector → server; `version` var set by ldflags |
| `settings.go` | env parsing + validation; constant-time token compare |
| `iface.go` | default-route interface detection from `/proc/net/route` |
| `nft.go` | run `nft -j list table ip <table>`, parse to `[]Rule` + `[]Masq` |
| `conntrack.go` | read `/proc/net/nf_conntrack` or `conntrack -L`, parse, group per origin |
| `procstats.go` | `/proc/net/dev`, `/proc/loadavg`, `/proc/meminfo`, `/proc/stat` (two-sample), conntrack sysctls |
| `stats.go` | `Collector`: composes the three readers into `Stats` and `Health` |
| `server.go` | `http.Handler` with auth middleware and the three routes |
| `*_test.go` | one test file per source file |
| `testdata/` | captured-and-anonymised fixtures |
| `build.sh` | cross-compile + sha256 |
| `install.sh` | relay prep + binary install + unit + self-check |
| `relay-agent.service` | hardened unit |
| `openapi.yml` | API contract |
| `README.md` | usage, install, env, endpoints |

---

### Task 1: Module skeleton, settings, token compare

**Files:**
- Create: `go.mod`, `settings.go`, `settings_test.go`, `.gitignore`

**Interfaces:**
- Produces:
  ```go
  type Settings struct {
      APIToken string
      Port     int
      Iface    string // "" means auto-detect
      NFTTable string
  }
  func LoadSettings(getenv func(string) string) (Settings, error)
  func (s Settings) TokenMatches(candidate string) bool
  ```

- [ ] **Step 1: Create go.mod and .gitignore**

```
cat > go.mod <<'EOF'
module github.com/akromjon/relay-agent

go 1.22
EOF
cat > .gitignore <<'EOF'
/dist/
/relay-agent
*.test
EOF
```

- [ ] **Step 2: Write the failing settings test**

`settings_test.go`:
```go
package main

import "testing"

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadSettingsDefaults(t *testing.T) {
	s, err := LoadSettings(envMap(map[string]string{"API_TOKEN": "abc123"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.APIToken != "abc123" {
		t.Errorf("APIToken = %q", s.APIToken)
	}
	if s.Port != 8080 {
		t.Errorf("Port = %d, want 8080", s.Port)
	}
	if s.Iface != "" {
		t.Errorf("Iface = %q, want empty (auto)", s.Iface)
	}
	if s.NFTTable != "chop_relay" {
		t.Errorf("NFTTable = %q", s.NFTTable)
	}
}

func TestLoadSettingsOverrides(t *testing.T) {
	s, err := LoadSettings(envMap(map[string]string{
		"API_TOKEN": " tok ", "RELAY_AGENT_PORT": "8082", "RELAY_IFACE": "ens3", "NFT_TABLE": "other",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.APIToken != "tok" || s.Port != 8082 || s.Iface != "ens3" || s.NFTTable != "other" {
		t.Errorf("got %+v", s)
	}
}

func TestLoadSettingsRejectsMissingToken(t *testing.T) {
	if _, err := LoadSettings(envMap(map[string]string{})); err == nil {
		t.Fatal("expected error for missing API_TOKEN")
	}
}

func TestLoadSettingsRejectsBadPort(t *testing.T) {
	for _, p := range []string{"0", "70000", "abc"} {
		if _, err := LoadSettings(envMap(map[string]string{"API_TOKEN": "x", "RELAY_AGENT_PORT": p})); err == nil {
			t.Errorf("port %q: expected error", p)
		}
	}
}

func TestTokenMatches(t *testing.T) {
	s := Settings{APIToken: "secret"}
	if !s.TokenMatches("secret") {
		t.Error("exact token should match")
	}
	if s.TokenMatches("Secret") || s.TokenMatches("") || s.TokenMatches("secret ") {
		t.Error("non-identical tokens must not match")
	}
	if (Settings{}).TokenMatches("") {
		t.Error("empty configured token must never match")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./... -run 'TestLoadSettings|TestTokenMatches' -v`
Expected: FAIL, `undefined: LoadSettings`

- [ ] **Step 4: Implement settings.go**

```go
package main

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"
)

// Settings is everything the agent reads from the environment.
type Settings struct {
	APIToken string
	Port     int
	Iface    string // empty = auto-detect from the default route
	NFTTable string
}

// LoadSettings reads the environment through getenv (injected for tests).
func LoadSettings(getenv func(string) string) (Settings, error) {
	s := Settings{
		APIToken: strings.TrimSpace(getenv("API_TOKEN")),
		Port:     8080,
		Iface:    strings.TrimSpace(getenv("RELAY_IFACE")),
		NFTTable: "chop_relay",
	}
	if s.APIToken == "" {
		return Settings{}, fmt.Errorf("API_TOKEN is required")
	}
	if raw := strings.TrimSpace(getenv("RELAY_AGENT_PORT")); raw != "" {
		p, err := strconv.Atoi(raw)
		if err != nil || p < 1 || p > 65535 {
			return Settings{}, fmt.Errorf("RELAY_AGENT_PORT must be 1-65535, got %q", raw)
		}
		s.Port = p
	}
	if t := strings.TrimSpace(getenv("NFT_TABLE")); t != "" {
		s.NFTTable = t
	}
	return s, nil
}

// TokenMatches compares in constant time. An empty configured token never matches.
func (s Settings) TokenMatches(candidate string) bool {
	if s.APIToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.APIToken), []byte(candidate)) == 1
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./... -run 'TestLoadSettings|TestTokenMatches' -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod .gitignore settings.go settings_test.go
git commit -m "feat: module skeleton and env settings with constant-time token compare"
```

---

### Task 2: Default-route interface detection

**Files:**
- Create: `iface.go`, `iface_test.go`, `testdata/proc-net-route.txt`

**Interfaces:**
- Produces:
  ```go
  // DefaultIface returns the interface carrying the default IPv4 route.
  func DefaultIface(procNetRoute []byte) (string, error)
  ```

- [ ] **Step 1: Add the fixture**

`testdata/proc-net-route.txt` (real format from a Regxa box; `Flags 0003` = UP|GATEWAY):
```
Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT                                                       
eth0	00000000	FE44FB96	0003	0	0	0	00000000	0	0	0                                                                               
eth0	0044FB96	00000000	0001	0	0	0	00FFFFFF	0	0	0                                                                               
```

- [ ] **Step 2: Write the failing test**

`iface_test.go`:
```go
package main

import (
	"os"
	"testing"
)

func TestDefaultIfaceFromFixture(t *testing.T) {
	b, err := os.ReadFile("testdata/proc-net-route.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DefaultIface(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != "eth0" {
		t.Errorf("got %q, want eth0", got)
	}
}

func TestDefaultIfacePrefersGatewayFlag(t *testing.T) {
	in := []byte("Iface\tDestination\tGateway\tFlags\n" +
		"ens3\t00000000\t00000000\t0001\n" + // default dest but no GATEWAY flag
		"ens16\t00000000\t0101A8C0\t0003\n")
	got, err := DefaultIface(in)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ens16" {
		t.Errorf("got %q, want ens16", got)
	}
}

func TestDefaultIfaceNoRoute(t *testing.T) {
	if _, err := DefaultIface([]byte("Iface\tDestination\tGateway\tFlags\n")); err == nil {
		t.Fatal("expected error when no default route")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./... -run TestDefaultIface -v`
Expected: FAIL, `undefined: DefaultIface`

- [ ] **Step 4: Implement iface.go**

```go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

const rtfGateway = 0x0002

// DefaultIface parses /proc/net/route and returns the interface of the first
// entry with destination 0.0.0.0 and the GATEWAY flag set. Falls back to any
// 0.0.0.0 destination if no entry carries the flag.
func DefaultIface(procNetRoute []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(procNetRoute))
	fallback := ""
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		if f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil {
			continue
		}
		if flags&rtfGateway != 0 {
			return f[0], nil
		}
		if fallback == "" {
			fallback = f[0]
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("no default route in /proc/net/route")
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./... -run TestDefaultIface -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add iface.go iface_test.go testdata/proc-net-route.txt
git commit -m "feat: detect default-route interface from /proc/net/route"
```

---

### Task 3: nftables JSON parser

**Files:**
- Create: `nft.go`, `nft_test.go`, `testdata/nft-chop_relay.json`, `testdata/nft-empty-table.json`

**Interfaces:**
- Produces:
  ```go
  type Rule struct {
      Proto      string  `json:"proto"`
      Port       int     `json:"port"`
      Origin     string  `json:"origin"`
      OriginPort int     `json:"origin_port"`
      NewFlows   *uint64 `json:"new_flows"`
      Bytes      *uint64 `json:"bytes"`
  }
  type Masq struct {
      Proto      string  `json:"proto"`
      Origin     string  `json:"origin"`
      OriginPort int     `json:"origin_port"`
      Packets    *uint64 `json:"packets"`
      Bytes      *uint64 `json:"bytes"`
  }
  type NFTRules struct {
      Rules []Rule `json:"rules"`
      Masq  []Masq `json:"masquerade"`
  }
  func ParseNFT(jsonOut []byte) (NFTRules, error)
  ```
- Consumes: nothing from other tasks.

- [ ] **Step 1: Add fixtures**

`testdata/nft-chop_relay.json` (shape captured from `nft -j list table ip chop_relay`, nft 1.0.9; addresses anonymised; one DNAT rule without a counter, one masquerade without counter):
```json
{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"table": {"family": "ip", "name": "chop_relay", "handle": 14}}, {"chain": {"family": "ip", "table": "chop_relay", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "chop_relay", "name": "postrouting", "handle": 2, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}}, {"rule": {"family": "ip", "table": "chop_relay", "chain": "prerouting", "handle": 3, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 2053}}, {"counter": {"packets": 126, "bytes": 54304}}, {"dnat": {"addr": "203.0.113.10", "port": 443}}]}}, {"rule": {"family": "ip", "table": "chop_relay", "chain": "prerouting", "handle": 5, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 2057}}, {"dnat": {"addr": "203.0.113.20", "port": 2407}}]}}, {"rule": {"family": "ip", "table": "chop_relay", "chain": "prerouting", "handle": 7, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "ens3"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}}, {"counter": {"packets": 258, "bytes": 14944}}, {"dnat": {"addr": "203.0.113.30", "port": 443}}]}}, {"rule": {"family": "ip", "table": "chop_relay", "chain": "postrouting", "handle": 4, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "203.0.113.10"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 443}}, {"counter": {"packets": 126, "bytes": 54304}}, {"masquerade": null}]}}, {"rule": {"family": "ip", "table": "chop_relay", "chain": "postrouting", "handle": 6, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "203.0.113.20"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 2407}}, {"masquerade": null}]}}]}
```

`testdata/nft-empty-table.json`:
```json
{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"table": {"family": "ip", "name": "chop_relay", "handle": 14}}, {"chain": {"family": "ip", "table": "chop_relay", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "chop_relay", "name": "postrouting", "handle": 2, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}}]}
```

- [ ] **Step 2: Write the failing test**

`nft_test.go`:
```go
package main

import (
	"os"
	"testing"
)

func u64(v uint64) *uint64 { return &v }

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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./... -run TestParseNFT -v`
Expected: FAIL, `undefined: ParseNFT`

- [ ] **Step 4: Implement nft.go**

```go
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

type nftExpr struct {
	Match      *nftMatch `json:"match"`
	Counter    *struct {
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
	} `json:"counter"`
	Dnat *struct {
		Addr string `json:"addr"`
		Port int    `json:"port"`
	} `json:"dnat"`
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
		var dnat *struct {
			Addr string `json:"addr"`
			Port int    `json:"port"`
		}
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./... -run TestParseNFT -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add nft.go nft_test.go testdata/nft-chop_relay.json testdata/nft-empty-table.json
git commit -m "feat: parse nft -j DNAT and masquerade rules with counters"
```

---

### Task 4: conntrack parser and per-origin grouping

**Files:**
- Create: `conntrack.go`, `conntrack_test.go`, `testdata/conntrack-L.txt`

**Interfaces:**
- Produces:
  ```go
  type Flow struct {
      Proto     string
      OrigSrc   string
      OrigDst   string
      OrigSport int
      OrigDport int
      ReplySrc  string
      ReplySport int
      Replied   bool
  }
  func ParseConntrack(text []byte) []Flow
  type OriginStats struct {
      Origin     string `json:"origin"`
      OriginPort int    `json:"origin_port"`
      Proto      string `json:"proto"`
      Flows      int    `json:"flows"`
      Replied    int    `json:"replied"`
      ClientIPs  int    `json:"client_ips"`
  }
  func GroupByOrigin(flows []Flow, rules []Rule) []OriginStats
  ```
- Consumes: `Rule` from Task 3.

- [ ] **Step 1: Add the fixture**

`testdata/conntrack-L.txt` (same line grammar as `/proc/net/nf_conntrack` minus the leading `ipv4 2` columns; anonymised from relay 21):
```
udp      17 29 src=198.51.100.11 dst=192.0.2.1 sport=50231 dport=2053 src=203.0.113.10 dst=192.0.2.1 sport=443 dport=50231 [ASSURED] mark=0 use=1
udp      17 27 src=198.51.100.11 dst=192.0.2.1 sport=50232 dport=2053 src=203.0.113.10 dst=192.0.2.1 sport=443 dport=50232 [ASSURED] mark=0 use=1
udp      17 28 src=198.51.100.12 dst=192.0.2.1 sport=41000 dport=2053 src=203.0.113.10 dst=192.0.2.1 sport=443 dport=41000 [ASSURED] mark=0 use=1
udp      17 12 src=198.51.100.13 dst=192.0.2.1 sport=41001 dport=2053 [UNREPLIED] src=203.0.113.10 dst=192.0.2.1 sport=443 dport=41001 mark=0 use=1
udp      17 29 src=198.51.100.14 dst=192.0.2.1 sport=60000 dport=2057 src=203.0.113.20 dst=192.0.2.1 sport=2407 dport=60000 [ASSURED] mark=0 use=1
tcp      6 98 TIME_WAIT src=198.51.100.99 dst=192.0.2.1 sport=27791 dport=22 src=192.0.2.1 dst=198.51.100.99 sport=22 dport=27791 [ASSURED] mark=0 use=1
udp      17 21 src=192.0.2.136 dst=192.0.2.255 sport=64512 dport=64512 [UNREPLIED] src=192.0.2.255 dst=192.0.2.136 sport=64512 dport=64512 mark=0 use=1
```

- [ ] **Step 2: Write the failing test**

`conntrack_test.go`:
```go
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./... -run 'TestParseConntrack|TestGroupByOrigin' -v`
Expected: FAIL, `undefined: ParseConntrack`

- [ ] **Step 4: Implement conntrack.go**

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./... -run 'TestParseConntrack|TestGroupByOrigin' -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add conntrack.go conntrack_test.go testdata/conntrack-L.txt
git commit -m "feat: parse conntrack entries and group reply state per DNAT origin"
```

---

### Task 5: /proc readers (netdev, loadavg, meminfo, cpu two-sample, sysctls)

**Files:**
- Create: `procstats.go`, `procstats_test.go`, `testdata/proc-net-dev.txt`, `testdata/proc-stat-a.txt`, `testdata/proc-stat-b.txt`, `testdata/proc-meminfo.txt`

**Interfaces:**
- Produces:
  ```go
  type NetDev struct { RxBytes, TxBytes, RxPackets, TxPackets, RxDrop, TxDrop uint64 }
  func ParseNetDev(text []byte, iface string) (NetDev, error)
  func ParseLoad1(text []byte) (float64, error)
  func ParseMemAvailableKB(text []byte) (uint64, error)
  type CPUSample struct { Idle, Steal, Total uint64 }
  func ParseCPUSample(text []byte) (CPUSample, error)
  func CPUPercent(a, b CPUSample) (idlePct, stealPct float64)
  func ReadUintFile(path string) *uint64   // nil when the file is absent
  ```

- [ ] **Step 1: Add fixtures**

`testdata/proc-net-dev.txt`:
```
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    9876    0    0    0     0          0         0  1234567    9876    0    0    0     0       0          0
  eth0: 4315119032  208335    0   13    0     0          0         0 110235507   65348    0    0    0     0       0          0
```

`testdata/proc-stat-a.txt`:
```
cpu  1000 0 500 8000 100 0 50 200 0 0
cpu0 1000 0 500 8000 100 0 50 200 0 0
intr 12345
ctxt 6789
```

`testdata/proc-stat-b.txt` (delta: idle +900, steal +50, total +1000):
```
cpu  1030 0 510 8900 105 0 55 250 0 0
cpu0 1030 0 510 8900 105 0 55 250 0 0
intr 12999
ctxt 7000
```

`testdata/proc-meminfo.txt`:
```
MemTotal:         958616 kB
MemFree:          569000 kB
MemAvailable:     690000 kB
Buffers:           20000 kB
```

- [ ] **Step 2: Write the failing test**

`procstats_test.go`:
```go
package main

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseNetDev(t *testing.T) {
	nd, err := ParseNetDev(mustRead(t, "proc-net-dev.txt"), "eth0")
	if err != nil {
		t.Fatal(err)
	}
	want := NetDev{RxBytes: 4315119032, RxPackets: 208335, RxDrop: 13, TxBytes: 110235507, TxPackets: 65348, TxDrop: 0}
	if nd != want {
		t.Errorf("got %+v, want %+v", nd, want)
	}
	if _, err := ParseNetDev(mustRead(t, "proc-net-dev.txt"), "ens3"); err == nil {
		t.Error("missing iface must error")
	}
}

func TestParseLoad1(t *testing.T) {
	v, err := ParseLoad1([]byte("0.02 0.05 0.01 1/123 4567\n"))
	if err != nil || v != 0.02 {
		t.Errorf("got %v %v", v, err)
	}
}

func TestParseMemAvailableKB(t *testing.T) {
	v, err := ParseMemAvailableKB(mustRead(t, "proc-meminfo.txt"))
	if err != nil || v != 690000 {
		t.Errorf("got %v %v", v, err)
	}
}

func TestCPUPercent(t *testing.T) {
	a, err := ParseCPUSample(mustRead(t, "proc-stat-a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseCPUSample(mustRead(t, "proc-stat-b.txt"))
	if err != nil {
		t.Fatal(err)
	}
	idle, steal := CPUPercent(a, b)
	if math.Abs(idle-90.0) > 0.01 || math.Abs(steal-5.0) > 0.01 {
		t.Errorf("idle=%v steal=%v, want 90/5", idle, steal)
	}
	if i, s := CPUPercent(a, a); i != 0 || s != 0 {
		t.Errorf("zero delta must yield 0/0, got %v/%v", i, s)
	}
}

func TestReadUintFileAbsent(t *testing.T) {
	if v := ReadUintFile(filepath.Join(t.TempDir(), "nope")); v != nil {
		t.Errorf("absent file must yield nil, got %v", *v)
	}
	p := filepath.Join(t.TempDir(), "n")
	os.WriteFile(p, []byte("262144\n"), 0o644)
	if v := ReadUintFile(p); v == nil || *v != 262144 {
		t.Errorf("got %v", v)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./... -run 'TestParseNetDev|TestParseLoad1|TestParseMemAvailableKB|TestCPUPercent|TestReadUintFile' -v`
Expected: FAIL, `undefined: ParseNetDev`

- [ ] **Step 4: Implement procstats.go**

```go
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// NetDev holds cumulative interface counters from /proc/net/dev.
type NetDev struct {
	RxBytes, TxBytes, RxPackets, TxPackets, RxDrop, TxDrop uint64
}

// ParseNetDev extracts one interface's counters.
// Column layout after "iface:": rx bytes packets errs drop fifo frame compressed multicast, tx bytes packets errs drop ...
func ParseNetDev(text []byte, iface string) (NetDev, error) {
	sc := bufio.NewScanner(bytes.NewReader(text))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(name) != iface {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 12 {
			return NetDev{}, fmt.Errorf("/proc/net/dev: short line for %s", iface)
		}
		u := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		return NetDev{
			RxBytes: u(0), RxPackets: u(1), RxDrop: u(3),
			TxBytes: u(8), TxPackets: u(9), TxDrop: u(11),
		}, nil
	}
	return NetDev{}, fmt.Errorf("/proc/net/dev: interface %q not found", iface)
}

// ParseLoad1 returns the 1-minute load average from /proc/loadavg.
func ParseLoad1(text []byte) (float64, error) {
	f := strings.Fields(string(text))
	if len(f) < 1 {
		return 0, fmt.Errorf("/proc/loadavg: empty")
	}
	return strconv.ParseFloat(f[0], 64)
}

// ParseMemAvailableKB returns MemAvailable from /proc/meminfo.
func ParseMemAvailableKB(text []byte) (uint64, error) {
	sc := bufio.NewScanner(bytes.NewReader(text))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "MemAvailable:") {
			f := strings.Fields(sc.Text())
			if len(f) >= 2 {
				return strconv.ParseUint(f[1], 10, 64)
			}
		}
	}
	return 0, fmt.Errorf("/proc/meminfo: MemAvailable not found")
}

// CPUSample is the aggregate "cpu" line of /proc/stat.
type CPUSample struct{ Idle, Steal, Total uint64 }

// ParseCPUSample reads the first "cpu " line. Fields: user nice system idle iowait irq softirq steal guest guest_nice.
func ParseCPUSample(text []byte) (CPUSample, error) {
	sc := bufio.NewScanner(bytes.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[0] != "cpu" {
			continue
		}
		var s CPUSample
		for i := 1; i < len(f); i++ {
			v, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				return CPUSample{}, err
			}
			s.Total += v
			switch i {
			case 4, 5: // idle + iowait
				s.Idle += v
			case 8:
				s.Steal = v
			}
		}
		return s, nil
	}
	return CPUSample{}, fmt.Errorf("/proc/stat: no cpu line")
}

// CPUPercent returns idle% and steal% over the interval a->b. Zero delta -> 0/0.
func CPUPercent(a, b CPUSample) (idlePct, stealPct float64) {
	total := float64(b.Total - a.Total)
	if b.Total <= a.Total {
		return 0, 0
	}
	return float64(b.Idle-a.Idle) * 100 / total, float64(b.Steal-a.Steal) * 100 / total
}

// ReadUintFile reads a single unsigned integer file (sysctl style). nil if absent/unparsable.
func ReadUintFile(path string) *uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return nil
	}
	return &v
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./... -run 'TestParseNetDev|TestParseLoad1|TestParseMemAvailableKB|TestCPUPercent|TestReadUintFile' -v`
Expected: PASS (5 tests)

- [ ] **Step 6: Commit**

```bash
git add procstats.go procstats_test.go testdata/proc-net-dev.txt testdata/proc-stat-a.txt testdata/proc-stat-b.txt testdata/proc-meminfo.txt
git commit -m "feat: /proc readers for netdev, load, memory, cpu steal and sysctl files"
```

---

### Task 6: Collector composing Stats and Health

**Files:**
- Create: `stats.go`, `stats_test.go`

**Interfaces:**
- Consumes: `ParseNFT`, `NFTRules` (Task 3); `ParseConntrack`, `GroupByOrigin`, `OriginStats` (Task 4); `ParseNetDev`, `ParseLoad1`, `ParseMemAvailableKB`, `ParseCPUSample`, `CPUPercent`, `ReadUintFile` (Task 5); `DefaultIface` (Task 2); `Settings` (Task 1).
- Produces:
  ```go
  type BoxStats struct { ... }   // see code
  type Stats struct { TS int64; Iface string; Rules []Rule; Origins []OriginStats; Box BoxStats; Warnings []string }
  type Health struct { Running bool; Version string; UptimeS int64; Iface string; IPForward *bool; ConntrackMax *uint64; NFTTablePresent bool }
  type Sources struct {            // injectable I/O
      NFT       func(table string) ([]byte, error)
      Conntrack func() ([]byte, error)
      ReadFile  func(path string) ([]byte, error)
      Sleep     func(d time.Duration)
      Now       func() time.Time
  }
  func DefaultSources() Sources
  type Collector struct { Settings Settings; Src Sources; Version string; Started time.Time }
  func (c *Collector) Iface() (string, error)
  func (c *Collector) Stats() (Stats, error)
  func (c *Collector) Health() Health
  ```

- [ ] **Step 1: Write the failing test**

`stats_test.go`:
```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestCollector -v`
Expected: FAIL, `undefined: Collector`

- [ ] **Step 3: Implement stats.go**

```go
package main

import (
	"fmt"
	"os"
	"time"
)

// BoxStats are host-level counters. Cumulative fields are diffed by the backend.
type BoxStats struct {
	RxBytes        uint64  `json:"rx_bytes"`
	TxBytes        uint64  `json:"tx_bytes"`
	RxPackets      uint64  `json:"rx_packets"`
	TxPackets      uint64  `json:"tx_packets"`
	RxDrop         uint64  `json:"rx_drop"`
	TxDrop         uint64  `json:"tx_drop"`
	ConntrackCount *uint64 `json:"conntrack_count"`
	ConntrackMax   *uint64 `json:"conntrack_max"`
	Load1          float64 `json:"load1"`
	MemAvailKB     uint64  `json:"mem_avail_kb"`
	CPUStealPct    float64 `json:"cpu_steal_pct"`
	CPUIdlePct     float64 `json:"cpu_idle_pct"`
}

// Stats is the /api/stats response.
type Stats struct {
	TS       int64         `json:"ts"`
	Iface    string        `json:"iface"`
	Rules    []Rule        `json:"rules"`
	Origins  []OriginStats `json:"origins"`
	Box      BoxStats      `json:"box"`
	Warnings []string      `json:"warnings"`
}

// Health is the /api/health response.
type Health struct {
	Running         bool    `json:"running"`
	Version         string  `json:"version"`
	UptimeS         int64   `json:"uptime_s"`
	Iface           string  `json:"iface"`
	IPForward       *bool   `json:"ip_forward"`
	ConntrackMax    *uint64 `json:"conntrack_max"`
	NFTTablePresent bool    `json:"nft_table_present"`
}

// Sources are the agent's I/O, injectable for tests.
type Sources struct {
	NFT       func(table string) ([]byte, error)
	Conntrack func() ([]byte, error)
	ReadFile  func(path string) ([]byte, error)
	Sleep     func(d time.Duration)
	Now       func() time.Time
}

// DefaultSources wires the real commands and files.
func DefaultSources() Sources {
	return Sources{NFT: runNFT, Conntrack: readConntrack, ReadFile: os.ReadFile, Sleep: time.Sleep, Now: time.Now}
}

// Collector assembles responses. It holds no mutable state between requests.
type Collector struct {
	Settings Settings
	Src      Sources
	Version  string
	Started  time.Time
}

const cpuSampleGap = 100 * time.Millisecond

// Iface returns the configured interface or auto-detects it.
func (c *Collector) Iface() (string, error) {
	if c.Settings.Iface != "" {
		return c.Settings.Iface, nil
	}
	b, err := c.Src.ReadFile("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("read /proc/net/route: %w", err)
	}
	return DefaultIface(b)
}

// Stats collects everything. Missing nft/conntrack degrade to empty lists
// plus a warning; a /proc read failure is a hard error.
func (c *Collector) Stats() (Stats, error) {
	s := Stats{TS: c.Src.Now().Unix(), Rules: []Rule{}, Origins: []OriginStats{}, Warnings: []string{}}

	iface, err := c.Iface()
	if err != nil {
		return Stats{}, err
	}
	s.Iface = iface

	if raw, err := c.Src.NFT(c.Settings.NFTTable); err != nil {
		s.Warnings = append(s.Warnings, err.Error())
	} else if parsed, err := ParseNFT(raw); err != nil {
		s.Warnings = append(s.Warnings, err.Error())
	} else {
		s.Rules = parsed.Rules
	}

	if raw, err := c.Src.Conntrack(); err != nil {
		s.Warnings = append(s.Warnings, err.Error())
	} else {
		s.Origins = GroupByOrigin(ParseConntrack(raw), s.Rules)
	}

	dev, err := c.Src.ReadFile("/proc/net/dev")
	if err != nil {
		return Stats{}, fmt.Errorf("read /proc/net/dev: %w", err)
	}
	nd, err := ParseNetDev(dev, iface)
	if err != nil {
		return Stats{}, err
	}
	s.Box.RxBytes, s.Box.TxBytes = nd.RxBytes, nd.TxBytes
	s.Box.RxPackets, s.Box.TxPackets = nd.RxPackets, nd.TxPackets
	s.Box.RxDrop, s.Box.TxDrop = nd.RxDrop, nd.TxDrop

	if b, err := c.Src.ReadFile("/proc/loadavg"); err == nil {
		s.Box.Load1, _ = ParseLoad1(b)
	} else {
		return Stats{}, fmt.Errorf("read /proc/loadavg: %w", err)
	}
	if b, err := c.Src.ReadFile("/proc/meminfo"); err == nil {
		s.Box.MemAvailKB, _ = ParseMemAvailableKB(b)
	} else {
		return Stats{}, fmt.Errorf("read /proc/meminfo: %w", err)
	}

	a, err := c.cpuSample()
	if err != nil {
		return Stats{}, err
	}
	c.Src.Sleep(cpuSampleGap)
	b, err := c.cpuSample()
	if err != nil {
		return Stats{}, err
	}
	s.Box.CPUIdlePct, s.Box.CPUStealPct = CPUPercent(a, b)

	s.Box.ConntrackCount = c.readUint("/proc/sys/net/netfilter/nf_conntrack_count")
	s.Box.ConntrackMax = c.readUint("/proc/sys/net/netfilter/nf_conntrack_max")
	return s, nil
}

// Health is cheap: no conntrack, no cpu sampling.
func (c *Collector) Health() Health {
	h := Health{Running: true, Version: c.Version, UptimeS: int64(c.Src.Now().Sub(c.Started).Seconds())}
	h.Iface, _ = c.Iface()
	if v := c.readUint("/proc/sys/net/ipv4/ip_forward"); v != nil {
		on := *v == 1
		h.IPForward = &on
	}
	h.ConntrackMax = c.readUint("/proc/sys/net/netfilter/nf_conntrack_max")
	if _, err := c.Src.NFT(c.Settings.NFTTable); err == nil {
		h.NFTTablePresent = true
	}
	return h
}

func (c *Collector) cpuSample() (CPUSample, error) {
	b, err := c.Src.ReadFile("/proc/stat")
	if err != nil {
		return CPUSample{}, fmt.Errorf("read /proc/stat: %w", err)
	}
	return ParseCPUSample(b)
}

func (c *Collector) readUint(path string) *uint64 {
	b, err := c.Src.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseUintBytes(b)
}
```

Also add to `procstats.go` (so `ReadUintFile` and the collector share one parser):
```go
// parseUintBytes parses a trimmed unsigned integer; nil on failure.
func parseUintBytes(b []byte) *uint64 {
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return nil
	}
	return &v
}
```
and change `ReadUintFile` body to:
```go
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseUintBytes(b)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -v`
Expected: all PASS (Tasks 1–6)

- [ ] **Step 5: Commit**

```bash
git add stats.go stats_test.go procstats.go
git commit -m "feat: collector composing nft, conntrack and /proc into Stats and Health"
```

---

### Task 7: HTTP server with key auth

**Files:**
- Create: `server.go`, `server_test.go`, `main.go`

**Interfaces:**
- Consumes: `Collector`, `Stats`, `Health`, `NFTRules` (Task 6/3), `Settings` (Task 1).
- Produces:
  ```go
  type APIServer struct { settings Settings; collector *Collector }
  func NewAPIServer(s Settings, c *Collector) *APIServer
  func (s *APIServer) Handler() http.Handler
  ```
  Routes: `GET /api/health`, `GET /api/stats`, `GET /api/rules`. Any other path or method under `/api/` → 404. Non-`/api/` paths → 404.

- [ ] **Step 1: Write the failing test**

`server_test.go`:
```go
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testServer(t *testing.T) http.Handler {
	t.Helper()
	settings := Settings{APIToken: "secret", Port: 8080, NFTTable: "chop_relay"}
	c := &Collector{Settings: settings, Src: fakeSources(t, nil, nil), Version: "test", Started: time.Now()}
	return NewAPIServer(settings, c).Handler()
}

func do(h http.Handler, method, path, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if key != "" {
		req.Header.Set("key", key)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestAuthMissingOrWrongKeyIs404(t *testing.T) {
	h := testServer(t)
	for _, key := range []string{"", "wrong", "Secret"} {
		for _, p := range []string{"/api/health", "/api/stats", "/api/rules"} {
			if rr := do(h, http.MethodGet, p, key); rr.Code != http.StatusNotFound {
				t.Errorf("%s key=%q: code %d, want 404", p, key, rr.Code)
			}
		}
	}
}

func TestHealthOK(t *testing.T) {
	rr := do(testServer(t), http.MethodGet, "/api/health", "secret")
	if rr.Code != 200 {
		t.Fatalf("code %d body %s", rr.Code, rr.Body)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type %q", ct)
	}
	var h Health
	if err := json.Unmarshal(rr.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if !h.Running || h.Iface != "eth0" || !h.NFTTablePresent {
		t.Errorf("health = %+v", h)
	}
}

func TestStatsOK(t *testing.T) {
	rr := do(testServer(t), http.MethodGet, "/api/stats", "secret")
	if rr.Code != 200 {
		t.Fatalf("code %d body %s", rr.Code, rr.Body)
	}
	var s Stats
	if err := json.Unmarshal(rr.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Rules) != 3 || s.Rules[0].Port != 2053 || s.Origins[0].Replied != 3 {
		t.Errorf("stats = %+v", s)
	}
	// JSON contract: nil counters serialise as null, present ones as numbers.
	body := rr.Body.String()
	if !contains(body, `"new_flows":126`) || !contains(body, `"new_flows":null`) {
		t.Errorf("counter serialisation wrong: %s", body)
	}
}

func TestRulesOK(t *testing.T) {
	rr := do(testServer(t), http.MethodGet, "/api/rules", "secret")
	if rr.Code != 200 {
		t.Fatalf("code %d", rr.Code)
	}
	var r NFTRules
	if err := json.Unmarshal(rr.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Rules) != 3 || len(r.Masq) != 2 {
		t.Errorf("rules = %+v", r)
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	h := testServer(t)
	if rr := do(h, http.MethodPost, "/api/stats", "secret"); rr.Code != 404 {
		t.Errorf("POST must be 404, got %d", rr.Code)
	}
	if rr := do(h, http.MethodGet, "/api/nope", "secret"); rr.Code != 404 {
		t.Errorf("unknown route must be 404, got %d", rr.Code)
	}
	if rr := do(h, http.MethodGet, "/", "secret"); rr.Code != 404 {
		t.Errorf("root must be 404, got %d", rr.Code)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (func() bool { for i := 0; i+len(sub) <= len(s); i++ { if s[i:i+len(sub)] == sub { return true } }; return false })() }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestAuth|TestHealthOK|TestStatsOK|TestRulesOK|TestUnknownRoute' -v`
Expected: FAIL, `undefined: NewAPIServer`

- [ ] **Step 3: Implement server.go**

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// APIServer exposes the collector over HTTP behind the `key` header.
type APIServer struct {
	settings  Settings
	collector *Collector
}

func NewAPIServer(s Settings, c *Collector) *APIServer {
	return &APIServer{settings: s, collector: c}
}

// Handler builds the mux. Every /api route is GET-only and authenticated;
// anything else is 404 so the agent does not advertise itself.
func (s *APIServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/health", s.authenticate(s.get(s.handleHealth)))
	mux.Handle("/api/stats", s.authenticate(s.get(s.handleStats)))
	mux.Handle("/api/rules", s.authenticate(s.get(s.handleRules)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return mux
}

func (s *APIServer) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.settings.TokenMatches(r.Header.Get("key")) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *APIServer) get(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		fn(w, r)
	})
}

func (s *APIServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.collector.Health())
}

func (s *APIServer) handleStats(w http.ResponseWriter, _ *http.Request) {
	st, err := s.collector.Stats()
	if err != nil {
		log.Printf("stats: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *APIServer) handleRules(w http.ResponseWriter, _ *http.Request) {
	raw, err := s.collector.Src.NFT(s.settings.NFTTable)
	if err != nil {
		writeJSON(w, http.StatusOK, NFTRules{Rules: []Rule{}, Masq: []Masq{}})
		return
	}
	parsed, err := ParseNFT(raw)
	if err != nil {
		log.Printf("rules: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, parsed)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode: %v", err)
	}
}
```

`main.go`:
```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// version is injected at build time: -ldflags="-X main.version=v0.1.0".
var version = "dev"

func main() {
	settings, err := LoadSettings(os.Getenv)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	collector := &Collector{Settings: settings, Src: DefaultSources(), Version: version, Started: time.Now()}
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", settings.Port),
		Handler:           NewAPIServer(settings, collector).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("relay-agent %s listening on %s", version, srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
```

- [ ] **Step 4: Run all tests and vet**

Run: `go vet ./... && go test ./... -v`
Expected: vet clean, all PASS

- [ ] **Step 5: Smoke run locally (no root needed; nft/conntrack absent on the Mac degrade to warnings)**

```bash
API_TOKEN=devtoken go run . &
sleep 1
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/api/health            # expect 404
curl -s -H "key: devtoken" http://127.0.0.1:8080/api/health                         # expect JSON, running:true
curl -s -H "key: devtoken" http://127.0.0.1:8080/api/stats | head -c 300; echo      # expect 500 on macOS (no /proc) — acceptable; Linux gives 200
kill %1
```

- [ ] **Step 6: Commit**

```bash
git add server.go server_test.go main.go
git commit -m "feat: authenticated HTTP API with health, stats and rules endpoints"
```

---

### Task 8: build.sh, systemd unit, openapi, README

**Files:**
- Create: `build.sh`, `relay-agent.service`, `openapi.yml`, `README.md`

- [ ] **Step 1: build.sh**

```bash
#!/usr/bin/env bash
# Cross-compile static binaries + sha256 into dist/. Usage: ./build.sh [version]
set -Eeuo pipefail
cd "$(dirname "$0")"
VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
mkdir -p dist
for ARCH in amd64 arm64; do
	OUT="dist/relay-agent-linux-${ARCH}"
	CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" \
		go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT}" .
	(cd dist && shasum -a 256 "relay-agent-linux-${ARCH}" > "relay-agent-linux-${ARCH}.sha256")
	ls -la "${OUT}"
done
echo "built ${VERSION}"
```

`chmod +x build.sh && ./build.sh v0.1.0-dev` — expect two binaries under ~5 MB each and two `.sha256` files.

- [ ] **Step 2: relay-agent.service**

```
[Unit]
Description=CHOP relay agent (read-only stats)
Documentation=https://github.com/akromjon/relay-agent
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/relay-agent/.env
ExecStart=/usr/local/bin/relay-agent
Restart=on-failure
RestartSec=3
MemoryMax=32M
CPUQuota=10%
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: openapi.yml**

```yaml
openapi: 3.0.3
info:
  title: CHOP relay-agent
  version: 0.1.0
  description: Read-only kernel counters from a relay box. All routes need header `key`.
servers:
  - url: http://{relay}:8080
paths:
  /api/health:
    get:
      summary: Liveness and box prerequisites
      responses:
        "200": {description: OK, content: {application/json: {schema: {$ref: "#/components/schemas/Health"}}}}
        "404": {description: Missing or wrong key}
  /api/stats:
    get:
      summary: DNAT counters, per-origin conntrack state, box counters
      responses:
        "200": {description: OK, content: {application/json: {schema: {$ref: "#/components/schemas/Stats"}}}}
        "404": {description: Missing or wrong key}
        "500": {description: A /proc read failed}
  /api/rules:
    get:
      summary: Current DNAT and masquerade map
      responses:
        "200": {description: OK, content: {application/json: {schema: {$ref: "#/components/schemas/NFTRules"}}}}
        "404": {description: Missing or wrong key}
components:
  schemas:
    Health:
      type: object
      properties:
        running: {type: boolean}
        version: {type: string}
        uptime_s: {type: integer}
        iface: {type: string}
        ip_forward: {type: boolean, nullable: true}
        conntrack_max: {type: integer, nullable: true}
        nft_table_present: {type: boolean}
    Rule:
      type: object
      properties:
        proto: {type: string}
        port: {type: integer}
        origin: {type: string}
        origin_port: {type: integer}
        new_flows: {type: integer, nullable: true, description: nat-hook counter = first packet per flow, cumulative}
        bytes: {type: integer, nullable: true}
    Masq:
      type: object
      properties:
        proto: {type: string}
        origin: {type: string}
        origin_port: {type: integer}
        packets: {type: integer, nullable: true}
        bytes: {type: integer, nullable: true}
    OriginStats:
      type: object
      properties:
        origin: {type: string}
        origin_port: {type: integer}
        proto: {type: string}
        flows: {type: integer}
        replied: {type: integer}
        client_ips: {type: integer}
    BoxStats:
      type: object
      properties:
        rx_bytes: {type: integer}
        tx_bytes: {type: integer}
        rx_packets: {type: integer}
        tx_packets: {type: integer}
        rx_drop: {type: integer}
        tx_drop: {type: integer}
        conntrack_count: {type: integer, nullable: true}
        conntrack_max: {type: integer, nullable: true}
        load1: {type: number}
        mem_avail_kb: {type: integer}
        cpu_steal_pct: {type: number}
        cpu_idle_pct: {type: number}
    Stats:
      type: object
      properties:
        ts: {type: integer}
        iface: {type: string}
        rules: {type: array, items: {$ref: "#/components/schemas/Rule"}}
        origins: {type: array, items: {$ref: "#/components/schemas/OriginStats"}}
        box: {$ref: "#/components/schemas/BoxStats"}
        warnings: {type: array, items: {type: string}}
    NFTRules:
      type: object
      properties:
        rules: {type: array, items: {$ref: "#/components/schemas/Rule"}}
        masquerade: {type: array, items: {$ref: "#/components/schemas/Masq"}}
```

- [ ] **Step 4: README.md**

```markdown
# relay-agent

Read-only stats agent for CHOP relay boxes. One static Go binary, no
dependencies, idle between requests. Reports nftables DNAT counters,
conntrack reply state per origin, and box counters over an authenticated
HTTP API so the backend can tell a blocked relay from a dead one from a
dead origin. Design: `docs/superpowers/specs/2026-09-04-relay-agent-design.md`.

## Install (bare Ubuntu/Debian relay, as root)

    ssh root@<relay> 'API_TOKEN=<token> bash -s' < install.sh

The installer also performs the standard relay prep (ip_forward, conntrack
limits, empty idempotent `chop_relay` table, `nftables.service`). It never
rewrites an `/etc/nftables.conf` that already contains `chop_relay`.

## Environment (`/etc/relay-agent/.env`)

| Var | Default | Meaning |
| --- | --- | --- |
| `API_TOKEN` | required | must match `relays.api_key` on the backend |
| `RELAY_AGENT_PORT` | `8080` | listen port (use 8082 on a box that is also a node) |
| `RELAY_IFACE` | auto | interface; auto = default-route interface |
| `NFT_TABLE` | `chop_relay` | table to read |

## Endpoints (header `key: <API_TOKEN>`; wrong key → 404)

    curl -H "key: $TOKEN" http://<relay>:8080/api/health
    curl -H "key: $TOKEN" http://<relay>:8080/api/stats
    curl -H "key: $TOKEN" http://<relay>:8080/api/rules

`rules[].new_flows` is a nat-hook counter: it counts the first packet of
each flow, not throughput. All counters are cumulative; diff them.

## Build

    ./build.sh v0.1.0      # dist/relay-agent-linux-{amd64,arm64} + .sha256

## Test

    go vet ./... && go test ./...

Parsers are pure functions over fixtures in `testdata/`; no root or Linux
needed.
```

- [ ] **Step 5: Verify build and commit**

```bash
chmod +x build.sh && ./build.sh v0.1.0-dev && ls -la dist/
git add build.sh relay-agent.service openapi.yml README.md
git commit -m "build: cross-compile script, hardened systemd unit, API contract and README"
```

---

### Task 9: install.sh (relay prep + agent install + self-check)

**Files:**
- Create: `install.sh`

- [ ] **Step 1: Write install.sh**

```bash
#!/usr/bin/env bash
# CHOP relay-agent installer. Run as root on Ubuntu/Debian. Idempotent.
#   ssh root@<relay> 'API_TOKEN=<token> bash -s' < install.sh
# Env: API_TOKEN (required on first install), RELAY_AGENT_PORT (8080),
#      RELAY_AGENT_VERSION (latest release tag), RELAY_AGENT_BINARY (local file, skips download)
set -Eeuo pipefail

REPO="akromjon/relay-agent"
BIN="/usr/local/bin/relay-agent"
ENV_DIR="/etc/relay-agent"
ENV_FILE="${ENV_DIR}/.env"
UNIT="/etc/systemd/system/relay-agent.service"
PORT="${RELAY_AGENT_PORT:-8080}"
NFT_CONF="/etc/nftables.conf"

log() { printf '[relay-agent] %s\n' "$*"; }
die() { printf '[relay-agent] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "run as root"
command -v systemctl >/dev/null || die "systemd required"

# --- 1. packages -------------------------------------------------------------
if command -v apt-get >/dev/null; then
	need=()
	command -v nft >/dev/null || need+=(nftables)
	command -v conntrack >/dev/null || need+=(conntrack)
	command -v curl >/dev/null || need+=(curl)
	if ((${#need[@]})); then
		log "installing: ${need[*]}"
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}" >/dev/null
	fi
else
	log "no apt-get: install nftables + conntrack by hand, then re-run"
	command -v nft >/dev/null && command -v conntrack >/dev/null || die "nft/conntrack missing"
fi

# --- 2. relay prep (matches the fleet runbook) --------------------------------
cat > /etc/sysctl.d/99-chop-relay.conf <<'EOF'
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_max = 262144
EOF
echo nf_conntrack > /etc/modules-load.d/chop-relay.conf
modprobe nf_conntrack 2>/dev/null || true
sysctl -q --system >/dev/null

if [[ -f "${NFT_CONF}" ]] && grep -q 'chop_relay' "${NFT_CONF}"; then
	log "nftables.conf already has chop_relay - leaving it untouched"
else
	[[ -f "${NFT_CONF}" && ! -f "${NFT_CONF}.stock" ]] && cp "${NFT_CONF}" "${NFT_CONF}.stock"
	cat > "${NFT_CONF}" <<'EOF'
#!/usr/sbin/nft -f
table ip chop_relay
delete table ip chop_relay

table ip chop_relay {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
	}
}
EOF
	log "wrote empty chop_relay table to ${NFT_CONF}"
fi
nft -f "${NFT_CONF}"
systemctl enable --now nftables >/dev/null 2>&1 || true

# --- 3. binary ----------------------------------------------------------------
case "$(uname -m)" in
	x86_64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) die "unsupported arch $(uname -m)" ;;
esac
TMP="$(mktemp -d)"; trap 'rm -rf "${TMP}"' EXIT
if [[ -n "${RELAY_AGENT_BINARY:-}" ]]; then
	cp "${RELAY_AGENT_BINARY}" "${TMP}/relay-agent"
else
	TAG="${RELAY_AGENT_VERSION:-$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)}"
	[[ -n "${TAG}" ]] || die "could not resolve latest release tag; set RELAY_AGENT_VERSION"
	BASE="https://github.com/${REPO}/releases/download/${TAG}"
	log "downloading ${TAG} (${ARCH})"
	curl -fsSL "${BASE}/relay-agent-linux-${ARCH}" -o "${TMP}/relay-agent"
	curl -fsSL "${BASE}/relay-agent-linux-${ARCH}.sha256" -o "${TMP}/sum"
	(cd "${TMP}" && sed "s#relay-agent-linux-${ARCH}#relay-agent#" sum | sha256sum -c --quiet -) || die "sha256 mismatch"
fi
install -m 0755 "${TMP}/relay-agent" "${BIN}"

# --- 4. env -------------------------------------------------------------------
mkdir -p "${ENV_DIR}"
if [[ -f "${ENV_FILE}" && -z "${API_TOKEN:-}" ]]; then
	log "keeping existing ${ENV_FILE}"
else
	[[ -n "${API_TOKEN:-}" ]] || die "API_TOKEN required on first install"
	umask 077
	cat > "${ENV_FILE}" <<EOF
API_TOKEN=${API_TOKEN}
RELAY_AGENT_PORT=${PORT}
EOF
	umask 022
	log "wrote ${ENV_FILE}"
fi

# --- 5. unit ------------------------------------------------------------------
SYSD_VER="$(systemctl --version | head -1 | awk '{print $2}')"
cat > "${UNIT}" <<'EOF'
[Unit]
Description=CHOP relay agent (read-only stats)
Documentation=https://github.com/akromjon/relay-agent
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/relay-agent/.env
ExecStart=/usr/local/bin/relay-agent
Restart=on-failure
RestartSec=3
MemoryMax=32M
CPUQuota=10%
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
if [[ "${SYSD_VER}" =~ ^[0-9]+$ ]] && ((SYSD_VER < 232)); then
	sed -i '/^MemoryMax=/d;/^CPUQuota=/d;/^ProtectSystem=strict/d' "${UNIT}"
	log "old systemd ${SYSD_VER}: dropped resource limits"
fi
systemctl daemon-reload
systemctl enable --now relay-agent >/dev/null
systemctl restart relay-agent

# --- 6. self-check ------------------------------------------------------------
TOKEN="$(sed -n 's/^API_TOKEN=//p' "${ENV_FILE}")"
for _ in 1 2 3 4 5; do
	if OUT="$(curl -fsS -m 3 -H "key: ${TOKEN}" "http://127.0.0.1:${PORT}/api/health" 2>/dev/null)" && [[ "${OUT}" == *'"running":true'* ]]; then
		log "OK ${OUT}"
		exit 0
	fi
	sleep 1
done
journalctl -u relay-agent -n 20 --no-pager >&2 || true
die "agent did not answer /api/health on :${PORT}"
```

- [ ] **Step 2: Shell-check locally**

Run: `bash -n install.sh && (command -v shellcheck >/dev/null && shellcheck install.sh || echo "shellcheck not installed, syntax OK")`
Expected: no syntax errors.

- [ ] **Step 3: Dry-run on an idle spare with a locally built binary (no GitHub release yet)**

Relay 30 (`<relay-30-ip>`) is a validated idle spare with zero user traffic. It already has `chop_relay` in `/etc/nftables.conf`, which exercises the "leave it untouched" branch.

```bash
./build.sh v0.1.0-dev
scp dist/relay-agent-linux-amd64 root@<relay-30-ip>:/root/relay-agent.bin
TOKEN="$(openssl rand -hex 24)"; echo "$TOKEN" > /private/tmp/claude-501/-Users-admin-mobile-app-ultimate-vpn-app/4ea2acce-e449-4d9f-b70b-0c988c1e51a1/scratchpad/relay30.token
ssh root@<relay-30-ip> "API_TOKEN=$TOKEN RELAY_AGENT_BINARY=/root/relay-agent.bin bash -s" < install.sh
ssh root@<relay-30-ip> "grep -c dnat /etc/nftables.conf; systemctl is-active relay-agent; curl -s -H 'key: $TOKEN' http://127.0.0.1:8080/api/stats | head -c 600; echo; ps -o rss=,pcpu= -C relay-agent"
```
Expected: installer prints `nftables.conf already has chop_relay - leaving it untouched`, `OK {...running:true...}`; the DNAT rule count in nftables.conf is unchanged from before (1 on relay 30); stats JSON shows the `2053 → <origin-ip>:443` rule with its counter; RSS under 10000 kB.

- [ ] **Step 4: Commit**

```bash
chmod +x install.sh
git add install.sh
git commit -m "build: installer with relay prep, checksum-verified binary, unit and self-check"
```

---

### Task 10: Tag v0.1.0, GitHub release, roll to the remaining spares

**Files:**
- none in repo (release + ops)

- [ ] **Step 1: Tag and build**

```bash
git tag -a v0.1.0 -m "relay-agent v0.1.0: read-only stats API"
./build.sh v0.1.0
git push origin main --tags
```

- [ ] **Step 2: Create the GitHub release with the four artifacts**

```bash
gh release create v0.1.0 dist/relay-agent-linux-amd64 dist/relay-agent-linux-amd64.sha256 dist/relay-agent-linux-arm64 dist/relay-agent-linux-arm64.sha256 --title "v0.1.0" --notes "Read-only stats agent: /api/health, /api/stats, /api/rules. See docs/superpowers/specs/2026-09-04-relay-agent-design.md."
```

- [ ] **Step 3: Install via the release path on spares 33, 34, 35 (idle, zero user traffic)**

```bash
S=/private/tmp/claude-501/-Users-admin-mobile-app-ultimate-vpn-app/4ea2acce-e449-4d9f-b70b-0c988c1e51a1/scratchpad
for R in <relay-33-ip> <relay-34-ip> <relay-35-ip>; do
  T="$(openssl rand -hex 24)"; echo "$R $T" >> $S/relay-tokens.txt
  ssh root@$R "API_TOKEN=$T bash -s" < install.sh
  ssh root@$R "curl -s -H 'key: $T' http://127.0.0.1:8080/api/health"; echo
done
```
Expected: each prints `downloading v0.1.0 (amd64)`, `OK {...}`, and health JSON with `nft_table_present:true`, `ip_forward:true`, `conntrack_max:262144`.

- [ ] **Step 4: Counter cross-check on one box (proves `new_flows` = nft counter)**

```bash
T=$(awk '/<relay-35-ip>/{print $2}' $S/relay-tokens.txt)
ssh root@<relay-35-ip> "A=\$(curl -s -H 'key: $T' http://127.0.0.1:8080/api/stats | sed -n 's/.*\"new_flows\":\([0-9]*\).*/\1/p'); B=\$(nft list table ip chop_relay | grep dport | grep -o 'packets [0-9]*' | awk '{print \$2}'); echo agent=\$A nft=\$B"
```
Expected: `agent=N nft=N` with equal N.

- [ ] **Step 5: Record tokens for the backend**

The tokens in `$S/relay-tokens.txt` and `$S/relay30.token` go into `relays.api_key` when the backend migration lands (separate project). Until then, paste them into the relay rows' `status_note` is NOT acceptable — keep them in the scratchpad file and hand them to the backend task.

- [ ] **Step 6: Note the rollout in memory**

Append to `/Users/admin/.claude/projects/-Users-admin-mobile-app-ultimate-vpn-app/memory/reference_relay_node_map.md`: which relays run `relay-agent v0.1.0`, the port, and that tokens live only in `relays.api_key` (pending) — never in notes.

---

## Self-review

**Spec coverage**
- Endpoints `/api/health`, `/api/stats`, `/api/rules` with `key` auth → Task 7. ✔
- `rules[]` from `nft -j`, nil counters when absent, non-443 origin ports → Task 3. ✔
- `origins[]` from conntrack with procfs fallback, zero rows per rule → Task 4. ✔
- `box` counters incl. two-sample CPU, conntrack sysctls nullable → Tasks 5–6. ✔
- Degradation (missing nft/conntrack → empty + warning; /proc failure → 500) → Task 6 tests + Task 7 handler. ✔
- Env vars and defaults → Task 1. ✔
- Iface autodetect from default route → Task 2. ✔
- Static amd64+arm64 build with ldflags version + sha256 → Task 8. ✔
- Hardened unit with MemoryMax/CPUQuota/CAP_NET_ADMIN/AF_NETLINK → Task 8/9. ✔
- Installer: packages, relay prep, never rewrite existing chop_relay, checksum verify, env 0600, systemd-version guard, self-check → Task 9. ✔
- Portability: apt-only with manual fallback, arch detect → Task 9. ✔
- Rollout to spares first, counter cross-check → Tasks 9–10. ✔
- Backend side (`relays.api_key`, poller) is explicitly out of this repo → not planned here, called out in Task 10 step 5. ✔

**Placeholder scan** — none. Every code step has full code; fixtures are complete.

**Type consistency** — `Rule`, `Masq`, `NFTRules` (T3) used unchanged in T4/T6/T7; `OriginStats` (T4) in T6/T7; `Sources` field names `NFT/Conntrack/ReadFile/Sleep/Now` match between `stats.go` and `fakeSources`; `parseUintBytes` defined in T6's amendment to `procstats.go` and used by both `ReadUintFile` and `Collector.readUint`; `contains` helper defined in `server_test.go` only.
