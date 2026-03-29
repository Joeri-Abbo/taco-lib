package vulndb

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	maxDBDownloadSize = 512 * 1024 * 1024 // 512 MB limit
)

// DownloadDB downloads a pre-built database file from a URL and installs it into the cache.
// The URL should point to a JSON file (optionally gzip-compressed with .gz extension).
func DownloadDB(ctx context.Context, cache *Cache, url string, progressFn func(downloaded, total int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept-Encoding", "gzip")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading database: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	// Set up reader with size limit
	reader := io.LimitReader(resp.Body, maxDBDownloadSize)

	// Handle gzip
	if resp.Header.Get("Content-Encoding") == "gzip" || filepath.Ext(url) == ".gz" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return fmt.Errorf("decompressing gzip: %w", err)
		}
		defer func() { _ = gz.Close() }()
		reader = gz
	}

	// Read all data
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading download: %w", err)
	}

	// Validate it's valid JSON with DBEntry structure
	var entries []DBEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("invalid database format: %w", err)
	}

	// Write to cache
	if err := cache.WriteDB(entries); err != nil {
		return fmt.Errorf("writing to cache: %w", err)
	}

	// Update meta with source URL
	meta := &CacheMeta{
		LastUpdated: time.Now(),
		EntryCount:  len(entries),
		SourceURL:   url,
		ETag:        resp.Header.Get("ETag"),
	}
	if err := cache.WriteMeta(meta); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}

	return nil
}

// LoadDBFromFile copies an external database file into the cache.
func LoadDBFromFile(cache *Cache, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	// Handle gzip files
	if filepath.Ext(path) == ".gz" {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening file: %w", err)
		}
		defer func() { _ = f.Close() }()

		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("decompressing gzip: %w", err)
		}
		defer func() { _ = gz.Close() }()

		data, err = io.ReadAll(gz)
		if err != nil {
			return fmt.Errorf("reading gzip data: %w", err)
		}
	}

	// Validate
	var entries []DBEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("invalid database format: %w", err)
	}

	// Write to cache
	if err := cache.WriteDB(entries); err != nil {
		return fmt.Errorf("writing to cache: %w", err)
	}

	// Update meta
	absPath, _ := filepath.Abs(path)
	meta := &CacheMeta{
		LastUpdated: time.Now(),
		EntryCount:  len(entries),
		SourceURL:   "file://" + absPath,
	}
	return cache.WriteMeta(meta)
}

// BuildDB fetches from NVD and writes a standalone database file to the given output path.
// This is intended for CI/CD pipelines that build a daily database artifact.
func BuildDB(ctx context.Context, outputPath string, days int, progressFn func(fetched, total int)) error {
	fetcher := NewFetcher()

	if days <= 0 {
		days = 120 // default: last 120 days
	}

	entries, err := fetcher.FetchRecent(ctx, days, progressFn)
	if err != nil {
		return fmt.Errorf("fetching vulnerabilities: %w", err)
	}

	// If an existing file exists at the output path, merge with it
	if _, statErr := os.Stat(outputPath); statErr == nil {
		existingData, readErr := os.ReadFile(outputPath)
		if readErr == nil {
			var existing []DBEntry
			if json.Unmarshal(existingData, &existing) == nil {
				entries = mergeEntries(existing, entries)
			}
		}
	}

	// Write the database file
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling database: %w", err)
	}

	// Write atomically
	tmpPath := outputPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming output file: %w", err)
	}

	// Also write a meta.json alongside it
	metaPath := filepath.Join(filepath.Dir(outputPath), "meta.json")
	meta := &CacheMeta{
		LastUpdated: time.Now(),
		EntryCount:  len(entries),
		SourceURL:   "nvd",
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(metaPath, metaData, 0644)

	return nil
}

// ExportGzip writes the cached database as a gzip-compressed file for distribution.
func ExportGzip(cache *Cache, outputPath string) error {
	if !cache.Exists() {
		return fmt.Errorf("no cached database found; run 'taco db update' first")
	}

	data, err := os.ReadFile(cache.DBPath())
	if err != nil {
		return fmt.Errorf("reading cached database: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz := gzip.NewWriter(f)
	gz.Comment = "TACO VulnDB"
	gz.ModTime = time.Now()

	if _, err := gz.Write(data); err != nil {
		return fmt.Errorf("writing gzip data: %w", err)
	}

	if err := gz.Close(); err != nil {
		return fmt.Errorf("closing gzip writer: %w", err)
	}

	return nil
}
