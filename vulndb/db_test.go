package vulndb

import (
	"path/filepath"
	"runtime"
	"testing"
)

func testDBPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata", "vulndb", "test-db.json")
}

func TestNewFromFile(t *testing.T) {
	db, err := NewFromFile(testDBPath())
	if err != nil {
		t.Fatalf("failed to load test db: %v", err)
	}
	defer func() { _ = db.Close() }()

	meta := db.Metadata()
	if meta.EntryCount != 8 {
		t.Errorf("expected 8 entries, got %d", meta.EntryCount)
	}
}

func TestLookup(t *testing.T) {
	db, err := NewFromFile(testDBPath())
	if err != nil {
		t.Fatalf("failed to load test db: %v", err)
	}
	defer func() { _ = db.Close() }()

	tests := []struct {
		name      string
		ecosystem string
		pkg       string
		version   string
		wantCount int
		wantID    string
	}{
		{
			name:      "vulnerable lodash",
			ecosystem: "npm",
			pkg:       "lodash",
			version:   "4.17.20",
			wantCount: 1,
			wantID:    "CVE-2024-0001",
		},
		{
			name:      "fixed lodash",
			ecosystem: "npm",
			pkg:       "lodash",
			version:   "4.17.21",
			wantCount: 0,
		},
		{
			name:      "vulnerable flask",
			ecosystem: "pip",
			pkg:       "flask",
			version:   "2.0.1",
			wantCount: 1,
			wantID:    "CVE-2024-0002",
		},
		{
			name:      "fixed flask",
			ecosystem: "pip",
			pkg:       "flask",
			version:   "2.3.3",
			wantCount: 0,
		},
		{
			name:      "vulnerable x/net",
			ecosystem: "go",
			pkg:       "golang.org/x/net",
			version:   "0.15.0",
			wantCount: 1,
			wantID:    "CVE-2024-0003",
		},
		{
			name:      "unknown package",
			ecosystem: "npm",
			pkg:       "nonexistent",
			version:   "1.0.0",
			wantCount: 0,
		},
		{
			name:      "case insensitive ecosystem",
			ecosystem: "NPM",
			pkg:       "lodash",
			version:   "4.17.20",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns, err := db.Lookup(tt.ecosystem, tt.pkg, tt.version)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(vulns) != tt.wantCount {
				t.Errorf("got %d vulns, want %d", len(vulns), tt.wantCount)
			}
			if tt.wantID != "" && len(vulns) > 0 && vulns[0].ID != tt.wantID {
				t.Errorf("got ID %s, want %s", vulns[0].ID, tt.wantID)
			}
		})
	}
}
