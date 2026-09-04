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
	if b.Total <= a.Total {
		return 0, 0
	}
	total := float64(b.Total - a.Total)
	return float64(b.Idle-a.Idle) * 100 / total, float64(b.Steal-a.Steal) * 100 / total
}

// parseUintBytes parses a trimmed unsigned integer; nil on failure.
func parseUintBytes(b []byte) *uint64 {
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

// ReadUintFile reads a single unsigned integer file (sysctl style). nil if absent/unparsable.
func ReadUintFile(path string) *uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseUintBytes(b)
}
