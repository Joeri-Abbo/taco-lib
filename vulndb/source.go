package vulndb

import "context"

// SourceName identifies a vulnerability data source.
type SourceName string

const (
	SourceNVD     SourceName = "nvd"
	SourceOSV     SourceName = "osv"
	SourceGHSA    SourceName = "ghsa"
	SourceAlpine  SourceName = "alpine-secdb"
	SourceDebian  SourceName = "debian"
	SourceUbuntu  SourceName = "ubuntu"
	SourceRedHat  SourceName = "redhat"
	SourceALAS    SourceName = "alas"
	SourceCISAKEV SourceName = "cisa-kev"
)

// AllSources lists all known source names in precedence order (highest first).
// For same ecosystem+package+CVE, earlier sources take priority.
var AllSources = []SourceName{
	SourceAlpine,
	SourceDebian,
	SourceUbuntu,
	SourceRedHat,
	SourceALAS,
	SourceGHSA,
	SourceOSV,
	SourceNVD,
	SourceCISAKEV,
}

// SourceFetcher is the interface each vulnerability source must implement.
type SourceFetcher interface {
	// Name returns the source identifier.
	Name() SourceName

	// FetchAll downloads all available vulnerability data from this source.
	FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error)

	// FetchRecent downloads vulnerability data modified in the last N days.
	FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error)
}

// sourcePrecedence maps source names to priority (lower = higher priority).
var sourcePrecedence map[SourceName]int

func init() {
	sourcePrecedence = make(map[SourceName]int, len(AllSources))
	for i, s := range AllSources {
		sourcePrecedence[s] = i
	}
}

// SourcePriority returns the priority of a source (lower = higher priority).
// Unknown sources get lowest priority.
func SourcePriority(s SourceName) int {
	if p, ok := sourcePrecedence[s]; ok {
		return p
	}
	return len(AllSources)
}

// DefaultSources returns the default set of enabled source names.
func DefaultSources() []SourceName {
	return []SourceName{
		SourceNVD,
		SourceOSV,
		SourceGHSA,
		SourceAlpine,
		SourceDebian,
		SourceUbuntu,
		SourceRedHat,
		SourceALAS,
		SourceCISAKEV,
	}
}
