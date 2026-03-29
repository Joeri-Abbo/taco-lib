package vulndb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCacheWithDir(t *testing.T) {
	cache := NewCacheWithDir("/tmp/test-cache")
	if cache.Dir != "/tmp/test-cache" {
		t.Errorf("expected dir /tmp/test-cache, got %s", cache.Dir)
	}
	if cache.MaxAge != DefaultMaxAge {
		t.Errorf("expected MaxAge %v, got %v", DefaultMaxAge, cache.MaxAge)
	}
}

func TestCache_DBPath(t *testing.T) {
	cache := NewCacheWithDir("/tmp/test-cache")
	want := filepath.Join("/tmp/test-cache", DefaultDBFile)
	if cache.DBPath() != want {
		t.Errorf("expected %s, got %s", want, cache.DBPath())
	}
}

func TestCache_MetaPath(t *testing.T) {
	cache := NewCacheWithDir("/tmp/test-cache")
	want := filepath.Join("/tmp/test-cache", DefaultMetaFile)
	if cache.MetaPath() != want {
		t.Errorf("expected %s, got %s", want, cache.MetaPath())
	}
}

func TestCache_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	if cache.Exists() {
		t.Error("expected cache to not exist initially")
	}

	// Create the DB file
	_ = os.WriteFile(cache.DBPath(), []byte("[]"), 0644)

	if !cache.Exists() {
		t.Error("expected cache to exist after writing DB file")
	}
}

func TestCache_WriteAndReadMeta(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	now := time.Now().Truncate(time.Second)
	meta := &CacheMeta{
		LastUpdated: now,
		EntryCount:  42,
		SourceURL:   "https://example.com/vulndb.json",
		ETag:        "abc123",
		Sources: map[string]SourceMeta{
			"nvd": {LastUpdated: now, EntryCount: 30},
			"osv": {LastUpdated: now, EntryCount: 12},
		},
	}

	if err := cache.WriteMeta(meta); err != nil {
		t.Fatalf("WriteMeta failed: %v", err)
	}

	got, err := cache.ReadMeta()
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	if got.EntryCount != 42 {
		t.Errorf("expected 42 entries, got %d", got.EntryCount)
	}
	if got.SourceURL != "https://example.com/vulndb.json" {
		t.Errorf("unexpected source URL: %s", got.SourceURL)
	}
	if got.ETag != "abc123" {
		t.Errorf("unexpected ETag: %s", got.ETag)
	}
	if len(got.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(got.Sources))
	}
}

func TestCache_ReadMeta_Missing(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	_, err := cache.ReadMeta()
	if err == nil {
		t.Error("expected error when reading missing meta")
	}
}

func TestCache_IsStale(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)
	cache.MaxAge = 1 * time.Hour

	// No meta file — should be stale
	stale, err := cache.IsStale()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stale {
		t.Error("expected stale when no meta exists")
	}

	// Write fresh meta
	meta := &CacheMeta{LastUpdated: time.Now()}
	_ = cache.WriteMeta(meta)

	stale, err = cache.IsStale()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stale {
		t.Error("expected not stale for fresh meta")
	}

	// Write old meta
	meta.LastUpdated = time.Now().Add(-2 * time.Hour)
	_ = cache.WriteMeta(meta)

	stale, err = cache.IsStale()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stale {
		t.Error("expected stale for old meta")
	}
}

func TestCache_WriteAndReadDB(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	entries := []DBEntry{
		{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm", Severity: "HIGH"},
		{ID: "CVE-2024-0002", Package: "flask", Ecosystem: "pip", Severity: "MEDIUM"},
	}

	if err := cache.WriteDB(entries); err != nil {
		t.Fatalf("WriteDB failed: %v", err)
	}

	if !cache.Exists() {
		t.Error("expected cache to exist after WriteDB")
	}

	// Verify the file is valid JSON
	data, err := os.ReadFile(cache.DBPath())
	if err != nil {
		t.Fatalf("reading DB file: %v", err)
	}

	var loaded []DBEntry
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("parsing DB file: %v", err)
	}
	if len(loaded) != 2 {
		t.Errorf("expected 2 entries, got %d", len(loaded))
	}

	// Verify metadata was written
	meta, err := cache.ReadMeta()
	if err != nil {
		t.Fatalf("reading meta after WriteDB: %v", err)
	}
	if meta.EntryCount != 2 {
		t.Errorf("expected meta entry count 2, got %d", meta.EntryCount)
	}
}

func TestCache_WriteAndReadSourceDB(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	entries := []DBEntry{
		{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm", Source: "nvd"},
	}

	if err := cache.WriteSourceDB(SourceNVD, entries); err != nil {
		t.Fatalf("WriteSourceDB failed: %v", err)
	}

	loaded, err := cache.ReadSourceDB(SourceNVD)
	if err != nil {
		t.Fatalf("ReadSourceDB failed: %v", err)
	}
	if len(loaded) != 1 {
		t.Errorf("expected 1 entry, got %d", len(loaded))
	}
	if loaded[0].ID != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001, got %s", loaded[0].ID)
	}
}

func TestCache_ReadSourceDB_Missing(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	_, err := cache.ReadSourceDB(SourceNVD)
	if err == nil {
		t.Error("expected error when reading missing source DB")
	}
}

func TestCache_ReadAllSourceDBs(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	// Write entries for two sources
	nvdEntries := []DBEntry{{ID: "CVE-2024-0001", Package: "lodash"}}
	osvEntries := []DBEntry{{ID: "CVE-2024-0002", Package: "flask"}, {ID: "CVE-2024-0003", Package: "requests"}}

	_ = cache.WriteSourceDB(SourceNVD, nvdEntries)
	_ = cache.WriteSourceDB(SourceOSV, osvEntries)

	all, err := cache.ReadAllSourceDBs()
	if err != nil {
		t.Fatalf("ReadAllSourceDBs failed: %v", err)
	}

	if len(all) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(all))
	}
	if len(all[SourceNVD]) != 1 {
		t.Errorf("expected 1 NVD entry, got %d", len(all[SourceNVD]))
	}
	if len(all[SourceOSV]) != 2 {
		t.Errorf("expected 2 OSV entries, got %d", len(all[SourceOSV]))
	}
}

func TestCache_ReadAllSourceDBs_NoSourcesDir(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	all, err := cache.ReadAllSourceDBs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("expected 0 sources, got %d", len(all))
	}
}

func TestCache_SourceDBPath(t *testing.T) {
	cache := NewCacheWithDir("/tmp/test-cache")
	got := cache.SourceDBPath(SourceNVD)
	want := filepath.Join("/tmp/test-cache", "sources", "nvd.json")
	if got != want {
		t.Errorf("expected %s, got %s", want, got)
	}
}

func TestCache_LoadDB(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	entries := []DBEntry{
		{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm", Severity: "HIGH", AffectedVersions: "<4.17.21"},
	}
	_ = cache.WriteDB(entries)

	db, err := cache.LoadDB()
	if err != nil {
		t.Fatalf("LoadDB failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	vulns, err := db.Lookup("npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if len(vulns) != 1 {
		t.Errorf("expected 1 vuln, got %d", len(vulns))
	}
}

func TestCache_LoadDB_NoDB(t *testing.T) {
	tmpDir := t.TempDir()
	cache := NewCacheWithDir(tmpDir)

	_, err := cache.LoadDB()
	if err == nil {
		t.Error("expected error when no DB exists")
	}
}
