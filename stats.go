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

	b, err := c.Src.ReadFile("/proc/loadavg")
	if err != nil {
		return Stats{}, fmt.Errorf("read /proc/loadavg: %w", err)
	}
	s.Box.Load1, _ = ParseLoad1(b)

	b, err = c.Src.ReadFile("/proc/meminfo")
	if err != nil {
		return Stats{}, fmt.Errorf("read /proc/meminfo: %w", err)
	}
	s.Box.MemAvailKB, _ = ParseMemAvailableKB(b)

	sampleA, err := c.cpuSample()
	if err != nil {
		return Stats{}, err
	}
	c.Src.Sleep(cpuSampleGap)
	sampleB, err := c.cpuSample()
	if err != nil {
		return Stats{}, err
	}
	s.Box.CPUIdlePct, s.Box.CPUStealPct = CPUPercent(sampleA, sampleB)

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
