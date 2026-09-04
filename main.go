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
