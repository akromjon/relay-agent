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
