package vulndb

import (
	"sort"
	"testing"
)

func TestMergeMultiSource_SingleSource(t *testing.T) {
	entries := map[SourceName][]DBEntry{
		SourceNVD: {
			{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm", Severity: "HIGH", Title: "Test vuln"},
		},
	}

	result := MergeMultiSource(entries)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	if result[0].ID != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001, got %s", result[0].ID)
	}
}

func TestMergeMultiSource_HigherPriorityWins(t *testing.T) {
	entries := map[SourceName][]DBEntry{
		SourceNVD: {
			{ID: "CVE-2024-0001", Package: "curl", Ecosystem: "apk", Severity: "MEDIUM", Title: "NVD title", Description: "NVD desc"},
		},
		SourceAlpine: {
			{ID: "CVE-2024-0001", Package: "curl", Ecosystem: "apk", Severity: "HIGH", Title: "Alpine title"},
		},
	}

	result := MergeMultiSource(entries)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	e := result[0]
	// Alpine has higher priority than NVD, so its severity and title should win
	if e.Severity != "HIGH" {
		t.Errorf("expected severity HIGH from alpine, got %s", e.Severity)
	}
	if e.Title != "Alpine title" {
		t.Errorf("expected title from alpine, got %s", e.Title)
	}
	// But blank description should be filled from NVD
	if e.Description != "NVD desc" {
		t.Errorf("expected description from NVD, got %s", e.Description)
	}
}

func TestMergeMultiSource_LowerPriorityFillsBlanks(t *testing.T) {
	entries := map[SourceName][]DBEntry{
		SourceGHSA: {
			{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm", Severity: "HIGH", Title: "GHSA title"},
		},
		SourceNVD: {
			{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm", Severity: "CRITICAL", Title: "NVD title", Description: "NVD desc", FixedIn: "1.2.3"},
		},
	}

	result := MergeMultiSource(entries)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	e := result[0]
	// GHSA has higher priority than NVD
	if e.Severity != "HIGH" {
		t.Errorf("expected severity HIGH from GHSA, got %s", e.Severity)
	}
	if e.Title != "GHSA title" {
		t.Errorf("expected title from GHSA, got %s", e.Title)
	}
	// Blanks filled from NVD
	if e.Description != "NVD desc" {
		t.Errorf("expected description filled from NVD, got %s", e.Description)
	}
	if e.FixedIn != "1.2.3" {
		t.Errorf("expected fixedIn filled from NVD, got %s", e.FixedIn)
	}
}

func TestMergeMultiSource_UnknownSeverityFilledFromLower(t *testing.T) {
	entries := map[SourceName][]DBEntry{
		SourceDebian: {
			{ID: "CVE-2024-0001", Package: "openssl", Ecosystem: "debian", Severity: "UNKNOWN", Title: "Debian title"},
		},
		SourceNVD: {
			{ID: "CVE-2024-0001", Package: "openssl", Ecosystem: "debian", Severity: "CRITICAL"},
		},
	}

	result := MergeMultiSource(entries)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	// Debian has higher priority but UNKNOWN severity, so NVD's severity should fill in
	if result[0].Severity != "CRITICAL" {
		t.Errorf("expected UNKNOWN severity to be replaced by CRITICAL, got %s", result[0].Severity)
	}
}

func TestMergeMultiSource_CISAKEVEnrichment(t *testing.T) {
	entries := map[SourceName][]DBEntry{
		SourceNVD: {
			{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm", Severity: "HIGH"},
			{ID: "CVE-2024-0002", Package: "flask", Ecosystem: "pip", Severity: "MEDIUM"},
		},
		SourceCISAKEV: {
			{ID: "CVE-2024-0001"}, // only CVE-2024-0001 is in KEV
		},
	}

	result := MergeMultiSource(entries)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}

	// Sort for deterministic results
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })

	if !result[0].KnownExploited {
		t.Error("CVE-2024-0001 should be marked as KnownExploited")
	}
	if result[1].KnownExploited {
		t.Error("CVE-2024-0002 should NOT be marked as KnownExploited")
	}
}

func TestMergeMultiSource_DifferentPackagesSameID(t *testing.T) {
	entries := map[SourceName][]DBEntry{
		SourceNVD: {
			{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm", Severity: "HIGH"},
			{ID: "CVE-2024-0001", Package: "underscore", Ecosystem: "npm", Severity: "MEDIUM"},
		},
	}

	result := MergeMultiSource(entries)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries (different packages), got %d", len(result))
	}
}

func TestMergeMultiSource_EmptySources(t *testing.T) {
	entries := map[SourceName][]DBEntry{}
	result := MergeMultiSource(entries)
	if len(result) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(result))
	}
}

func TestMergeMultiSource_ReferencesFilledFromLower(t *testing.T) {
	entries := map[SourceName][]DBEntry{
		SourceGHSA: {
			{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm"},
		},
		SourceNVD: {
			{ID: "CVE-2024-0001", Package: "lodash", Ecosystem: "npm", References: []string{"https://example.com"}},
		},
	}

	result := MergeMultiSource(entries)
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	if len(result[0].References) != 1 {
		t.Errorf("expected references filled from NVD, got %v", result[0].References)
	}
}
