package vulndb

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultCacheDir  = ".taco/db"
	DefaultDBFile    = "vulndb.json"
	DefaultMetaFile  = "meta.json"
	DefaultMaxAge    = 24 * time.Hour
)

// SourceMeta tracks per-source update metadata.
type SourceMeta struct {
	LastUpdated time.Time `json:"last_updated"`
	EntryCount  int       `json:"entry_count"`
}

// CacheMeta stores metadata about the cached database.
type CacheMeta struct {
	LastUpdated time.Time                `json:"last_updated"`
	ETag        string                   `json:"etag,omitempty"`
	SourceURL   string                   `json:"source_url,omitempty"`
	EntryCount  int                      `json:"entry_count"`
	Sources     map[string]SourceMeta    `json:"sources,omitempty"`
}

// Cache manages the local vulnerability database cache.
type Cache struct {
	Dir    string
	MaxAge time.Duration
}

// NewCache creates a cache manager using the default cache directory (~/.taco/db).
func NewCache() (*Cache, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home directory: %w", err)
	}

	dir := filepath.Join(home, DefaultCacheDir)
	return &Cache{
		Dir:    dir,
		MaxAge: DefaultMaxAge,
	}, nil
}

// NewCacheWithDir creates a cache manager using a custom directory.
func NewCacheWithDir(dir string) *Cache {
	return &Cache{
		Dir:    dir,
		MaxAge: DefaultMaxAge,
	}
}

// DBPath returns the path to the cached database file.
func (c *Cache) DBPath() string {
	return filepath.Join(c.Dir, DefaultDBFile)
}

// MetaPath returns the path to the cache metadata file.
func (c *Cache) MetaPath() string {
	return filepath.Join(c.Dir, DefaultMetaFile)
}

// Exists checks if a cached database exists.
func (c *Cache) Exists() bool {
	_, err := os.Stat(c.DBPath())
	return err == nil
}

// IsStale checks if the cached database is older than MaxAge.
func (c *Cache) IsStale() (bool, error) {
	meta, err := c.ReadMeta()
	if err != nil {
		return true, nil // if we can't read meta, treat as stale
	}

	age := time.Since(meta.LastUpdated)
	return age > c.MaxAge, nil
}

// ReadMeta reads the cache metadata.
func (c *Cache) ReadMeta() (*CacheMeta, error) {
	data, err := os.ReadFile(c.MetaPath())
	if err != nil {
		return nil, fmt.Errorf("reading cache meta: %w", err)
	}

	var meta CacheMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parsing cache meta: %w", err)
	}

	return &meta, nil
}

// WriteMeta writes the cache metadata.
func (c *Cache) WriteMeta(meta *CacheMeta) error {
	if err := os.MkdirAll(c.Dir, 0755); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cache meta: %w", err)
	}

	return os.WriteFile(c.MetaPath(), data, 0644)
}

// SourceDBPath returns the path to a per-source database file.
func (c *Cache) SourceDBPath(source SourceName) string {
	return filepath.Join(c.Dir, "sources", string(source)+".json")
}

// SourcesDir returns the path to the sources directory.
func (c *Cache) SourcesDir() string {
	return filepath.Join(c.Dir, "sources")
}

// WriteSourceDB writes entries for a single source to its own file.
func (c *Cache) WriteSourceDB(source SourceName, entries []DBEntry) error {
	dir := c.SourcesDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating sources directory: %w", err)
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling source %s: %w", source, err)
	}

	path := c.SourceDBPath(source)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing source %s: %w", source, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming source %s: %w", source, err)
	}

	return nil
}

// ReadSourceDB reads entries for a single source from its file.
func (c *Cache) ReadSourceDB(source SourceName) ([]DBEntry, error) {
	data, err := os.ReadFile(c.SourceDBPath(source))
	if err != nil {
		return nil, err
	}

	var entries []DBEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing source %s: %w", source, err)
	}

	return entries, nil
}

// ReadAllSourceDBs reads all per-source files and returns them keyed by source name.
func (c *Cache) ReadAllSourceDBs() (map[SourceName][]DBEntry, error) {
	result := make(map[SourceName][]DBEntry)

	dir := c.SourcesDir()
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return result, nil // no sources dir yet
	}

	for _, de := range dirEntries {
		if de.IsDir() || filepath.Ext(de.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(de.Name(), ".json")
		entries, err := c.ReadSourceDB(SourceName(name))
		if err != nil {
			continue
		}
		result[SourceName(name)] = entries
	}

	return result, nil
}

// WriteDB writes vulnerability entries to the cache atomically (write to temp, then rename).
func (c *Cache) WriteDB(entries []DBEntry) error {
	if err := os.MkdirAll(c.Dir, 0755); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling vulndb: %w", err)
	}

	// Write to temp file first for atomicity
	tmpPath := c.DBPath() + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing temp db file: %w", err)
	}

	if err := os.Rename(tmpPath, c.DBPath()); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming temp db file: %w", err)
	}

	// Update metadata
	meta := &CacheMeta{
		LastUpdated: time.Now(),
		EntryCount:  len(entries),
	}
	return c.WriteMeta(meta)
}

// LoadDB loads the cached database.
func (c *Cache) LoadDB() (DB, error) {
	if !c.Exists() {
		return nil, fmt.Errorf("no cached database found at %s; run 'taco db update' first", c.DBPath())
	}

	stale, _ := c.IsStale()
	if stale {
		fmt.Fprintf(os.Stderr, "warning: vulnerability database is stale (older than %s); run 'taco db update'\n", c.MaxAge)
	}

	return NewFromFile(c.DBPath())
}
