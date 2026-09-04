package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if !strings.Contains(body, `"new_flows":126`) || !strings.Contains(body, `"new_flows":null`) {
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
