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
