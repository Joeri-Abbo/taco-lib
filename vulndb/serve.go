package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// ServeOptions configures the database server.
type ServeOptions struct {
	Addr  string // listen address, e.g. ":8080"
	Cache *Cache
}

// Serve starts a lightweight HTTP server that hosts the cached database file.
// Other TACO instances can point `taco db download --url http://host:port/vulndb.json` at this.
func Serve(ctx context.Context, opts ServeOptions) error {
	if !opts.Cache.Exists() {
		return fmt.Errorf("no cached database found at %s; run 'taco db update' first", opts.Cache.DBPath())
	}

	mux := http.NewServeMux()

	// Serve the database file
	mux.HandleFunc("/vulndb.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, opts.Cache.DBPath())
	})

	// Serve the gzip version
	mux.HandleFunc("/vulndb.json.gz", func(w http.ResponseWriter, r *http.Request) {
		gzPath := opts.Cache.DBPath() + ".gz"

		// Build gzip on the fly if it doesn't exist or is older than the DB
		dbInfo, _ := os.Stat(opts.Cache.DBPath())
		gzInfo, gzErr := os.Stat(gzPath)

		if gzErr != nil || (dbInfo != nil && gzInfo != nil && dbInfo.ModTime().After(gzInfo.ModTime())) {
			if err := ExportGzip(opts.Cache, gzPath); err != nil {
				http.Error(w, "failed to compress database", http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Encoding", "gzip")
		http.ServeFile(w, r, gzPath)
	})

	// Serve metadata
	mux.HandleFunc("/meta.json", func(w http.ResponseWriter, r *http.Request) {
		meta, err := opts.Cache.ReadMeta()
		if err != nil {
			http.Error(w, "no metadata available", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	})

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status := map[string]any{
			"status": "ok",
			"db":     opts.Cache.Exists(),
		}
		if meta, err := opts.Cache.ReadMeta(); err == nil {
			status["last_updated"] = meta.LastUpdated
			status["entry_count"] = meta.EntryCount
			stale, _ := opts.Cache.IsStale()
			status["stale"] = stale
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})

	server := &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	listener, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", opts.Addr, err)
	}

	fmt.Fprintf(os.Stderr, "Serving TACO VulnDB at http://%s\n", listener.Addr())
	fmt.Fprintf(os.Stderr, "  GET /vulndb.json     — download database (JSON)\n")
	fmt.Fprintf(os.Stderr, "  GET /vulndb.json.gz  — download database (gzip)\n")
	fmt.Fprintf(os.Stderr, "  GET /meta.json       — database metadata\n")
	fmt.Fprintf(os.Stderr, "  GET /health          — health check\n")

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}
