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
