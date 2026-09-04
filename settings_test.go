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
