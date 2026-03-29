package vulndb

import (
	"testing"
)

func TestVersionMatches(t *testing.T) {
	tests := []struct {
		name       string
		installed  string
		constraint string
		want       bool
	}{
		{"wildcard", "1.0.0", "*", true},
		{"empty constraint", "1.0.0", "", true},
		{"less than match", "1.0.0", "<2.0.0", true},
		{"less than no match", "3.0.0", "<2.0.0", false},
		{"less than equal match", "2.0.0", "<=2.0.0", true},
		{"less than equal no match", "2.0.1", "<=2.0.0", false},
		{"greater than match", "3.0.0", ">2.0.0", true},
		{"greater than no match", "1.0.0", ">2.0.0", false},
		{"greater equal match", "2.0.0", ">=2.0.0", true},
		{"greater equal no match", "1.9.9", ">=2.0.0", false},
		{"exact match", "1.2.3", "=1.2.3", true},
		{"exact no match", "1.2.4", "=1.2.3", false},
		{"range match", "1.5.0", ">=1.0.0,<2.0.0", true},
		{"range lower bound", "1.0.0", ">=1.0.0,<2.0.0", true},
		{"range upper bound no match", "2.0.0", ">=1.0.0,<2.0.0", false},
		{"range below", "0.9.0", ">=1.0.0,<2.0.0", false},
		{"v prefix", "v1.0.0", "<2.0.0", true},
		{"patch version", "4.17.20", "<4.17.21", true},
		{"patch version no match", "4.17.21", "<4.17.21", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionMatches(tt.installed, tt.constraint)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("VersionMatches(%q, %q) = %v, want %v", tt.installed, tt.constraint, got, tt.want)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.0", 1},
		{"v1.0.0", "1.0.0", 0},
		{"1.0", "1.0.0", -1},
		// Debian epoch
		{"1:1.0.0", "0:2.0.0", 1},
		{"0:1.0.0", "1:0.5.0", -1},
		// Debian revision
		{"1.0.0-1", "1.0.0-2", -1},
		{"1.0.0-10", "1.0.0-2", 1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got, err := CompareVersions(tt.a, tt.b)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsVersionLessThan(t *testing.T) {
	less, err := IsVersionLessThan("1.0.0", "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !less {
		t.Error("expected 1.0.0 < 2.0.0")
	}

	less, err = IsVersionLessThan("2.0.0", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if less {
		t.Error("expected 2.0.0 NOT < 1.0.0")
	}
}
