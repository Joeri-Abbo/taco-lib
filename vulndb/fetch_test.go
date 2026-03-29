package vulndb

import (
	"testing"
)

func TestParseCPE(t *testing.T) {
	tests := []struct {
		cpe       string
		wantEco   string
		wantPkg   string
	}{
		{"cpe:2.3:a:nodejs:express:*:*:*:*:*:*:*:*", "npm", "express"},
		{"cpe:2.3:a:python:flask:*:*:*:*:*:*:*:*", "pip", "flask"},
		{"cpe:2.3:a:golang:net:*:*:*:*:*:*:*:*", "go", "net"},
		{"cpe:2.3:a:debian:openssl:*:*:*:*:*:*:*:*", "debian", "openssl"},
		{"cpe:2.3:a:alpine:curl:*:*:*:*:*:*:*:*", "apk", "curl"},
		{"cpe:2.3:a:npmjs:lodash:*:*:*:*:*:*:*:*", "npm", "lodash"},
		{"cpe:2.3:a:pypi:requests:*:*:*:*:*:*:*:*", "pip", "requests"},
		{"cpe:2.3:a:redhat:kernel:*:*:*:*:*:*:*:*", "rpm", "kernel"},
		{"cpe:2.3:a:somevendor:someproduct:*:*:*:*:*:*:*:*", "somevendor", "someproduct"},
		{"too:short", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.cpe, func(t *testing.T) {
			eco, pkg := parseCPE(tt.cpe)
			if eco != tt.wantEco {
				t.Errorf("ecosystem: got %q, want %q", eco, tt.wantEco)
			}
			if pkg != tt.wantPkg {
				t.Errorf("package: got %q, want %q", pkg, tt.wantPkg)
			}
		})
	}
}

func TestBuildConstraint(t *testing.T) {
	tests := []struct {
		name  string
		match nvdCPEMatch
		want  string
	}{
		{
			name:  "end excluding only",
			match: nvdCPEMatch{VersionEndExcluding: "1.2.3"},
			want:  "<1.2.3",
		},
		{
			name:  "start including and end excluding",
			match: nvdCPEMatch{VersionStartIncluding: "1.0.0", VersionEndExcluding: "2.0.0"},
			want:  ">=1.0.0,<2.0.0",
		},
		{
			name:  "end including",
			match: nvdCPEMatch{VersionEndIncluding: "3.0.0"},
			want:  "<=3.0.0",
		},
		{
			name:  "start excluding",
			match: nvdCPEMatch{VersionStartExcluding: "1.0.0"},
			want:  ">1.0.0",
		},
		{
			name:  "all bounds",
			match: nvdCPEMatch{VersionStartIncluding: "1.0.0", VersionEndIncluding: "2.0.0"},
			want:  ">=1.0.0,<=2.0.0",
		},
		{
			name:  "no bounds with specific version in CPE",
			match: nvdCPEMatch{Criteria: "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*"},
			want:  "=1.5.0",
		},
		{
			name:  "no bounds with wildcard in CPE",
			match: nvdCPEMatch{Criteria: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
			want:  "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildConstraint(tt.match)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSeverity(t *testing.T) {
	tests := []struct {
		name    string
		metrics nvdMetrics
		want    string
	}{
		{
			name: "v3.1 metric",
			metrics: nvdMetrics{
				CvssMetricV31: []nvdCVSSMetric{
					{CVSSData: struct {
						BaseSeverity string  `json:"baseSeverity"`
						BaseScore    float64 `json:"baseScore"`
					}{BaseSeverity: "critical"}},
				},
			},
			want: "CRITICAL",
		},
		{
			name: "v3.0 fallback",
			metrics: nvdMetrics{
				CvssMetricV30: []nvdCVSSMetric{
					{CVSSData: struct {
						BaseSeverity string  `json:"baseSeverity"`
						BaseScore    float64 `json:"baseScore"`
					}{BaseSeverity: "high"}},
				},
			},
			want: "HIGH",
		},
		{
			name: "v2 fallback",
			metrics: nvdMetrics{
				CvssMetricV2: []nvdCVSSMetricV2{
					{BaseSeverity: "medium"},
				},
			},
			want: "MEDIUM",
		},
		{
			name:    "no metrics",
			metrics: nvdMetrics{},
			want:    "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSeverity(tt.metrics)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractDescription(t *testing.T) {
	descs := []nvdDescription{
		{Lang: "es", Value: "Descripción en español"},
		{Lang: "en", Value: "English description that is quite long for testing truncation behavior"},
	}

	// No truncation
	got := extractDescription(descs, 0)
	if got != "English description that is quite long for testing truncation behavior" {
		t.Errorf("unexpected description: %s", got)
	}

	// With truncation
	got = extractDescription(descs, 20)
	if got != "English description ..." {
		t.Errorf("unexpected truncated description: %s", got)
	}

	// Empty
	got = extractDescription(nil, 0)
	if got != "" {
		t.Errorf("expected empty description, got %s", got)
	}

	// Non-English fallback
	got = extractDescription([]nvdDescription{{Lang: "es", Value: "Solo español"}}, 0)
	if got != "Solo español" {
		t.Errorf("expected fallback to first desc, got %s", got)
	}
}

func TestMergeEntries(t *testing.T) {
	existing := []DBEntry{
		{ID: "CVE-2024-0001", Package: "lodash", Severity: "HIGH"},
		{ID: "CVE-2024-0002", Package: "flask", Severity: "MEDIUM"},
	}

	newEntries := []DBEntry{
		{ID: "CVE-2024-0001", Package: "lodash", Severity: "CRITICAL"}, // update
		{ID: "CVE-2024-0003", Package: "requests", Severity: "LOW"},    // new
	}

	result := mergeEntries(existing, newEntries)
	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(result))
	}

	// CVE-2024-0001 should be updated
	if result[0].Severity != "CRITICAL" {
		t.Errorf("expected updated severity CRITICAL, got %s", result[0].Severity)
	}
	// CVE-2024-0002 unchanged
	if result[1].Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %s", result[1].Severity)
	}
	// CVE-2024-0003 added
	if result[2].ID != "CVE-2024-0003" {
		t.Errorf("expected CVE-2024-0003, got %s", result[2].ID)
	}
}

func TestNewSourceFetcherByName(t *testing.T) {
	tests := []struct {
		name SourceName
		want bool
	}{
		{SourceNVD, true},
		{SourceOSV, true},
		{SourceGHSA, true},
		{SourceAlpine, true},
		{SourceDebian, true},
		{SourceUbuntu, true},
		{SourceRedHat, true},
		{SourceALAS, true},
		{SourceCISAKEV, true},
		{SourceName("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.name), func(t *testing.T) {
			f := NewSourceFetcherByName(tt.name)
			if (f != nil) != tt.want {
				t.Errorf("NewSourceFetcherByName(%q): got nil=%v, want nil=%v", tt.name, f == nil, !tt.want)
			}
		})
	}
}

func TestNewFetchersForSources(t *testing.T) {
	names := []SourceName{SourceNVD, SourceOSV, SourceName("invalid")}
	fetchers := NewFetchersForSources(names)
	if len(fetchers) != 2 {
		t.Errorf("expected 2 fetchers (invalid skipped), got %d", len(fetchers))
	}
}
