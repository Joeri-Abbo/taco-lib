package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const osvBucketBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// OSVFetcher downloads vulnerability data from the OSV.dev GCS bucket.
// This uses the bulk export (all.zip per ecosystem) which is more reliable
// than the query API for fetching entire ecosystems.
type OSVFetcher struct {
	HTTPClient *http.Client
	BaseURL    string
}

var _ SourceFetcher = (*OSVFetcher)(nil)

func NewOSVFetcher() *OSVFetcher {
	return &OSVFetcher{
		HTTPClient: &http.Client{Timeout: 300 * time.Second},
		BaseURL:    osvBucketBaseURL,
	}
}

func (f *OSVFetcher) Name() SourceName { return SourceOSV }

// osvEcosystems lists the OSV ecosystem names we care about and their TACO mapping.
var osvEcosystems = map[string]string{
	"Go":         "go",
	"npm":        "npm",
	"PyPI":       "pip",
	"crates.io":  "cargo",
	"RubyGems":   "gem",
	"Maven":      "maven",
	"Packagist":  "composer",
	"NuGet":      "nuget",
	"Pub":        "pub",
	"Hex":        "hex",
}

// osvVulnerability represents a vulnerability in OSV format.
type osvVulnerability struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Details   string        `json:"details"`
	Aliases   []string      `json:"aliases"`
	Severity  []osvSeverity `json:"severity"`
	Affected  []osvAffected `json:"affected"`
	References []osvRef     `json:"references"`
	Modified  string        `json:"modified"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package  osvPackage   `json:"package"`
	Ranges   []osvRange   `json:"ranges"`
	Versions []string     `json:"versions"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRange struct {
	Type   string      `json:"type"`
	Events []osvEvent  `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type osvRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func (f *OSVFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	type ecoResult struct {
		entries []DBEntry
		err     error
	}

	results := make(chan ecoResult, len(osvEcosystems))
	for osvEco := range osvEcosystems {
		go func(eco string) {
			entries, err := f.fetchEcosystemZip(ctx, eco)
			if err != nil {
				results <- ecoResult{err: fmt.Errorf("fetching OSV ecosystem %s: %w", eco, err)}
				return
			}
			results <- ecoResult{entries: entries}
		}(osvEco)
	}

	var allEntries []DBEntry
	total := 0
	for range osvEcosystems {
		r := <-results
		if r.err != nil {
			continue
		}
		allEntries = append(allEntries, r.entries...)
		total += len(r.entries)
		if progressFn != nil {
			progressFn(total, 0)
		}
	}

	return allEntries, nil
}

func (f *OSVFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	// Bulk export doesn't support date filtering; fetch all and filter.
	allEntries, err := f.FetchAll(ctx, progressFn)
	if err != nil {
		return nil, err
	}

	if days <= 0 {
		return allEntries, nil
	}

	// Filter by modified date.
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	// We don't store modified on DBEntry, so return all for now.
	// The merge will handle dedup.
	recent := append([]DBEntry{}, allEntries...)
	_ = cutoff // TODO: filter when modified date is tracked
	return recent, nil
}

// fetchEcosystemZip downloads the all.zip for an ecosystem and parses each entry.
func (f *OSVFetcher) fetchEcosystemZip(ctx context.Context, ecosystem string) ([]DBEntry, error) {
	url := fmt.Sprintf("%s/%s/all.zip", f.BaseURL, ecosystem)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV bucket returned status %d for %s", resp.StatusCode, ecosystem)
	}

	// Read entire zip into memory (these are typically 1-50 MB).
	data, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20)) // 200 MB limit
	if err != nil {
		return nil, fmt.Errorf("reading zip for %s: %w", ecosystem, err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening zip for %s: %w", ecosystem, err)
	}

	var allEntries []DBEntry
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		var v osvVulnerability
		if err := json.NewDecoder(rc).Decode(&v); err != nil {
			_ = rc.Close()
			continue
		}
		_ = rc.Close()

		entries := transformOSVVuln(v, ecosystem)
		allEntries = append(allEntries, entries...)
	}

	return allEntries, nil
}

func transformOSVVuln(v osvVulnerability, fetchedEcosystem string) []DBEntry {
	var entries []DBEntry

	// Use CVE alias as ID if available, otherwise use OSV ID.
	id := v.ID
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			id = alias
			break
		}
	}

	severity := osvExtractSeverity(v.Severity)
	refs := make([]string, 0, len(v.References))
	for _, r := range v.References {
		refs = append(refs, r.URL)
	}

	title := v.Summary
	description := v.Details
	if len(description) > 500 {
		description = description[:500] + "..."
	}

	for _, aff := range v.Affected {
		eco, ok := osvEcosystems[aff.Package.Ecosystem]
		if !ok {
			// Try base ecosystem (e.g., "Debian:11" -> check "Debian")
			base := strings.Split(aff.Package.Ecosystem, ":")[0]
			eco, ok = osvEcosystems[base]
			if !ok {
				continue
			}
		}

		constraint, fixedIn := osvBuildConstraint(aff.Ranges)

		entries = append(entries, DBEntry{
			ID:               id,
			Severity:         severity,
			Ecosystem:        eco,
			Package:          aff.Package.Name,
			AffectedVersions: constraint,
			FixedIn:          fixedIn,
			Title:            title,
			Description:      description,
			References:       refs,
			Source:           string(SourceOSV),
		})
	}

	return entries
}

func osvExtractSeverity(sevs []osvSeverity) string {
	for _, s := range sevs {
		if s.Type == "CVSS_V3" {
			return cvssV3ScoreToSeverity(s.Score)
		}
	}
	return "UNKNOWN"
}

func cvssV3ScoreToSeverity(vector string) string {
	// A proper implementation would parse the CVSS vector; return UNKNOWN
	// and let NVD enrichment fill in the severity during merge.
	return "UNKNOWN"
}

func osvBuildConstraint(ranges []osvRange) (constraint, fixedIn string) {
	for _, r := range ranges {
		var introduced, fixed string
		for _, ev := range r.Events {
			if ev.Introduced != "" {
				introduced = ev.Introduced
			}
			if ev.Fixed != "" {
				fixed = ev.Fixed
			}
			if ev.LastAffected != "" && fixed == "" {
				fixed = ev.LastAffected
			}
		}

		if introduced != "" && fixed != "" {
			if introduced == "0" {
				constraint = "<" + fixed
			} else {
				constraint = ">=" + introduced + ",<" + fixed
			}
			fixedIn = fixed
			return
		}
		if introduced != "" {
			if introduced == "0" {
				constraint = "*"
			} else {
				constraint = ">=" + introduced
			}
			return
		}
		if fixed != "" {
			constraint = "<" + fixed
			fixedIn = fixed
			return
		}
	}

	return "*", ""
}
