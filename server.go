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
