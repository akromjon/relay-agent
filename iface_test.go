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
