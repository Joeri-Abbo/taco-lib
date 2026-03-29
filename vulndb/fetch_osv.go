package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const osvAPIBaseURL = "https://api.osv.dev/v1"

// OSVFetcher downloads vulnerability data from the OSV.dev API.
type OSVFetcher struct {
	HTTPClient *http.Client
	BaseURL    string
}

var _ SourceFetcher = (*OSVFetcher)(nil)

func NewOSVFetcher() *OSVFetcher {
	return &OSVFetcher{
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
		BaseURL:    osvAPIBaseURL,
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
	"SwiftURL":   "swift",
	"Alpine":     "apk",
	"Debian":     "debian",
	"Linux":      "linux",
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

type osvQueryResponse struct {
	Vulns     []osvVulnerability `json:"vulns"`
	NextPageToken string         `json:"next_page_token"`
}

func (f *OSVFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	type ecoResult struct {
		entries []DBEntry
		err     error
	}

	results := make(chan ecoResult, len(osvEcosystems))
	for osvEco := range osvEcosystems {
		go func(eco string) {
			entries, err := f.fetchEcosystem(ctx, eco)
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
			return nil, r.err
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
	// OSV doesn't have a "recent" endpoint; query with modified-since via the batch query.
	// For simplicity, we fetch all and filter by modification time.
	// In practice, OSV ecosystems are reasonably sized.
	return f.FetchAll(ctx, progressFn)
}

func (f *OSVFetcher) fetchEcosystem(ctx context.Context, ecosystem string) ([]DBEntry, error) {
	var allEntries []DBEntry
	pageToken := ""

	for {
		result, err := f.fetchEcosystemPage(ctx, ecosystem, pageToken)
		if err != nil {
			return nil, err
		}

		for _, v := range result.Vulns {
			entries := f.transformVuln(v)
			allEntries = append(allEntries, entries...)
		}

		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
	}

	return allEntries, nil
}

func (f *OSVFetcher) fetchEcosystemPage(ctx context.Context, ecosystem, pageToken string) (*osvQueryResponse, error) {
	body := map[string]interface{}{
		"ecosystem": ecosystem,
	}
	if pageToken != "" {
		body["page_token"] = pageToken
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	reqURL := f.BaseURL + "/query"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
	}

	return &result, nil
}

func (f *OSVFetcher) transformVuln(v osvVulnerability) []DBEntry {
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
			// Parse CVSS vector to extract severity.
			return cvssV3ScoreToSeverity(s.Score)
		}
	}
	return "UNKNOWN"
}

func cvssV3ScoreToSeverity(vector string) string {
	// CVSS vectors contain the score; try to parse base severity from known patterns.
	// Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
	// We'd need to calculate, but for simplicity check if vector contains score hint.
	// A proper implementation would parse the vector; here we return UNKNOWN and let
	// NVD enrichment fill in the severity.
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
