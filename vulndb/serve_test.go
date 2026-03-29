package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func startTestServer(t *testing.T, cache *Cache) (string, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	opts := ServeOptions{
		Addr:  addr,
		Cache: cache,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(ctx, opts)
	}()

	// Wait for server to be ready
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr, cancel
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	t.Fatalf("server did not start in time")
	return "", nil
}

func TestServe_HealthEndpoint(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)
	_ = cache.WriteDB(sampleEntries())

	addr, cancel := startTestServer(t, cache)
	defer cancel()

	resp, err := http.Get(fmt.Sprintf("http://%s/health", addr))
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decoding health response: %v", err)
	}

	if health["status"] != "ok" {
		t.Errorf("expected status ok, got %v", health["status"])
	}
	if health["db"] != true {
		t.Errorf("expected db true, got %v", health["db"])
	}
}

func TestServe_VulnDBEndpoint(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)
	_ = cache.WriteDB(sampleEntries())

	addr, cancel := startTestServer(t, cache)
	defer cancel()

	resp, err := http.Get(fmt.Sprintf("http://%s/vulndb.json", addr))
	if err != nil {
		t.Fatalf("vulndb request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var entries []DBEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("decoding vulndb response: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestServe_MetaEndpoint(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)
	_ = cache.WriteDB(sampleEntries())

	addr, cancel := startTestServer(t, cache)
	defer cancel()

	resp, err := http.Get(fmt.Sprintf("http://%s/meta.json", addr))
	if err != nil {
		t.Fatalf("meta request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var meta CacheMeta
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decoding meta response: %v", err)
	}

	if meta.EntryCount != 2 {
		t.Errorf("expected 2 entries in meta, got %d", meta.EntryCount)
	}
}

func TestServe_NoCache(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Serve(ctx, ServeOptions{Addr: "127.0.0.1:0", Cache: cache})
	if err == nil {
		t.Error("expected error when no cached database exists")
	}
}
