// Package vulndb provides vulnerability database access with local caching.
package vulndb

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Joeri-Abbo/taco-lib/types"
)

// DBEntry is the on-disk format for a vulnerability record in the JSON database.
type DBEntry struct {
	ID               string   `json:"id"`
	Severity         string   `json:"severity"`
	Ecosystem        string   `json:"ecosystem"`
	Package          string   `json:"package"`
	AffectedVersions string   `json:"affected_versions"` // e.g. "<1.2.3" or ">=1.0.0,<1.2.3"
	FixedIn          string   `json:"fixed_in,omitempty"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	References       []string `json:"references,omitempty"`
	Source           string   `json:"source,omitempty"`
	KnownExploited   bool     `json:"known_exploited,omitempty"`
	CvssScore        float64  `json:"cvss_score,omitempty"`
}

// DBMeta holds metadata about the vulnerability database.
type DBMeta struct {
	LastUpdated time.Time `json:"last_updated"`
	EntryCount  int       `json:"entry_count"`
	Source      string    `json:"source"`
}

// DB is the abstraction for vulnerability lookups.
type DB interface {
	Lookup(ecosystem, pkg, version string) ([]types.Vulnerability, error)
	Metadata() DBMeta
	Close() error
}

// jsonDB is a JSON-file-backed implementation of DB.
type jsonDB struct {
	mu      sync.RWMutex
	index   map[string]map[string][]DBEntry // ecosystem -> package -> entries
	meta    DBMeta
	entries []DBEntry
}

// NewFromFile loads a vulnerability database from a JSON file.
func NewFromFile(path string) (DB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading vulndb file: %w", err)
	}

	var entries []DBEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing vulndb file: %w", err)
	}

	db := &jsonDB{
		entries: entries,
		index:   make(map[string]map[string][]DBEntry),
		meta: DBMeta{
			EntryCount: len(entries),
			Source:     path,
		},
	}

	// Check file modification time for LastUpdated
	info, err := os.Stat(path)
	if err == nil {
		db.meta.LastUpdated = info.ModTime()
	}

	// Build index
	for _, e := range entries {
		eco := strings.ToLower(e.Ecosystem)
		pkg := strings.ToLower(e.Package)
		if db.index[eco] == nil {
			db.index[eco] = make(map[string][]DBEntry)
		}
		db.index[eco][pkg] = append(db.index[eco][pkg], e)
	}

	return db, nil
}

// Lookup finds all known vulnerabilities for a (package, version) pair in an ecosystem.
func (db *jsonDB) Lookup(ecosystem, pkg, version string) ([]types.Vulnerability, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	eco := strings.ToLower(ecosystem)
	p := strings.ToLower(pkg)

	entries, ok := db.index[eco][p]
	if !ok {
		return nil, nil
	}

	var vulns []types.Vulnerability
	for _, e := range entries {
		matched, err := VersionMatches(version, e.AffectedVersions)
		if err != nil {
			continue // skip entries with unparseable version constraints
		}
		if !matched {
			continue
		}

		vulns = append(vulns, types.Vulnerability{
			ID:             e.ID,
			Severity:       types.ParseSeverity(e.Severity),
			Package:        e.Package,
			Ecosystem:      e.Ecosystem,
			Installed:      version,
			FixedIn:        e.FixedIn,
			Title:          e.Title,
			Description:    e.Description,
			References:     e.References,
			Source:         e.Source,
			KnownExploited: e.KnownExploited,
		})
	}

	return vulns, nil
}

// Metadata returns information about the database.
func (db *jsonDB) Metadata() DBMeta {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.meta
}

// Close is a no-op for the JSON DB.
func (db *jsonDB) Close() error {
	return nil
}
