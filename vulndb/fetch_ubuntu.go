package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ubuntuCVEAPIURL = "https://ubuntu.com/security/cves.json"

// UbuntuFetcher downloads vulnerability data from the Ubuntu CVE Tracker.
type UbuntuFetcher struct {
	HTTPClient *http.Client
	BaseURL    string
}

var _ SourceFetcher = (*UbuntuFetcher)(nil)

func NewUbuntuFetcher() *UbuntuFetcher {
	return &UbuntuFetcher{
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
		BaseURL:    ubuntuCVEAPIURL,
	}
}

func (f *UbuntuFetcher) Name() SourceName { return SourceUbuntu }

type ubuntuCVEResponse struct {
	CVEs   []ubuntuCVE `json:"cves"`
	Offset int         `json:"offset"`
	Limit  int         `json:"limit"`
	Total  int         `json:"total_results"`
}

type ubuntuCVE struct {
	ID          string                `json:"id"`
	Description string                `json:"description"`
	Priority    string                `json:"priority"`
	UpdatedAt   time.Time             `json:"updated_at"`
	Packages    []ubuntuPackageStatus `json:"packages"`
	References  []string              `json:"references"`
}

type ubuntuPackageStatus struct {
	Name     string                     `json:"name"`
	Statuses []ubuntuReleaseStatus      `json:"statuses"`
}

type ubuntuReleaseStatus struct {
	ReleaseName    string `json:"release_codename"`
	Status         string `json:"status"`
	PocketVersion  string `json:"pocket"`
	Description    string `json:"description"`
}

// ubuntuActiveReleases are the Ubuntu releases we track.
var ubuntuActiveReleases = map[string]bool{
	"noble":  true, // 24.04 LTS
	"jammy":  true, // 22.04 LTS
	"focal":  true, // 20.04 LTS
	"mantic": true, // 23.10
	"lunar":  true, // 23.04
}

func (f *UbuntuFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	return f.fetchPaginated(ctx, "", progressFn)
}

// ubuntuConcurrency controls how many concurrent page requests we make.
const ubuntuConcurrency = 10

func (f *UbuntuFetcher) fetchPaginated(ctx context.Context, extraQuery string, progressFn func(fetched, total int)) ([]DBEntry, error) {
	limit := 20

	// First request to discover total count.
	firstURL := fmt.Sprintf("%s?limit=%d&offset=0%s", f.BaseURL, limit, extraQuery)
	firstEntries, rawCount, total, err := f.fetchPage(ctx, firstURL)
	if err != nil {
		return nil, err
	}
	if progressFn != nil {
		progressFn(rawCount, total)
	}
	if rawCount < limit || total <= limit {
		return firstEntries, nil
	}

	// Build list of remaining offsets.
	var offsets []int
	for o := limit; o < total; o += limit {
		offsets = append(offsets, o)
	}

	// Fetch remaining pages concurrently.
	type pageResult struct {
		offset  int
		entries []DBEntry
		err     error
	}

	resultsCh := make(chan pageResult, len(offsets))
	sem := make(chan struct{}, ubuntuConcurrency)

	var wg sync.WaitGroup
	for _, o := range offsets {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				resultsCh <- pageResult{offset: offset, err: ctx.Err()}
				return
			default:
			}

			url := fmt.Sprintf("%s?limit=%d&offset=%d%s", f.BaseURL, limit, offset, extraQuery)
			entries, _, _, fetchErr := f.fetchPage(ctx, url)
			resultsCh <- pageResult{offset: offset, entries: entries, err: fetchErr}
		}(o)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	allEntries := firstEntries
	fetched := rawCount
	for r := range resultsCh {
		if r.err != nil {
			return nil, fmt.Errorf("fetching offset %d: %w", r.offset, r.err)
		}
		allEntries = append(allEntries, r.entries...)
		fetched += len(r.entries)
		if progressFn != nil {
			progressFn(fetched, total)
		}
	}

	return allEntries, nil
}

func (f *UbuntuFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	cutoff := time.Now().AddDate(0, 0, -days)
	var allEntries []DBEntry
	offset := 0
	limit := 20

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		url := fmt.Sprintf("%s?limit=%d&offset=%d&sort_by=updated&order=descending", f.BaseURL, limit, offset)
		raw, entries, rawCount, total, err := f.fetchPageRaw(ctx, url)
		if err != nil {
			return nil, err
		}

		allEntries = append(allEntries, entries...)
		if progressFn != nil {
			progressFn(len(allEntries), total)
		}

		// Check if the oldest CVE on this page is before our cutoff.
		pastCutoff := false
		for _, cve := range raw {
			if cve.UpdatedAt.Before(cutoff) {
				pastCutoff = true
				break
			}
		}

		if pastCutoff || rawCount < limit {
			break
		}

		offset += limit
		time.Sleep(200 * time.Millisecond)
	}

	return allEntries, nil
}

func (f *UbuntuFetcher) fetchPage(ctx context.Context, url string) ([]DBEntry, int, int, error) {
	_, entries, count, total, err := f.fetchPageRaw(ctx, url)
	return entries, count, total, err
}

// fetchPageRaw returns (rawCVEs, entries, rawCVECount, totalResults, error).
func (f *UbuntuFetcher) fetchPageRaw(ctx context.Context, url string) ([]ubuntuCVE, []DBEntry, int, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	resp, err := doWithRetry(f.HTTPClient, req, 3)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("ubuntu CVE API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, 0, 0, fmt.Errorf("ubuntu CVE API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result ubuntuCVEResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, 0, 0, fmt.Errorf("decoding Ubuntu CVE response: %w", err)
	}

	var entries []DBEntry
	for _, cve := range result.CVEs {
		entries = append(entries, f.transformCVE(cve)...)
	}

	return result.CVEs, entries, len(result.CVEs), result.Total, nil
}

func (f *UbuntuFetcher) transformCVE(cve ubuntuCVE) []DBEntry {
	var entries []DBEntry

	severity := ubuntuPriorityToSeverity(cve.Priority)
	description := cve.Description
	if len(description) > 500 {
		description = description[:500] + "..."
	}

	for _, pkg := range cve.Packages {
		for _, status := range pkg.Statuses {
			if !ubuntuActiveReleases[status.ReleaseName] {
				continue
			}
			if status.Status == "not-affected" || status.Status == "DNE" {
				continue
			}

			constraint := "*"
			fixedIn := ""
			if status.Description != "" && status.Status == "released" {
				fixedIn = status.Description
				constraint = "<" + fixedIn
			}

			entries = append(entries, DBEntry{
				ID:               cve.ID,
				Severity:         severity,
				Ecosystem:        "ubuntu",
				Package:          pkg.Name,
				AffectedVersions: constraint,
				FixedIn:          fixedIn,
				Title:            fmt.Sprintf("%s in %s", cve.ID, pkg.Name),
				Description:      description,
				References:       cve.References,
				Source:           string(SourceUbuntu),
			})
		}
	}

	return entries
}

func ubuntuPriorityToSeverity(priority string) string {
	switch strings.ToLower(priority) {
	case "negligible":
		return "LOW"
	case "low":
		return "LOW"
	case "medium":
		return "MEDIUM"
	case "high":
		return "HIGH"
	case "critical":
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}
