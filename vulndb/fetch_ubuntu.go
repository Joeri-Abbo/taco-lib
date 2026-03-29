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
	var allEntries []DBEntry
	offset := 0
	limit := 20

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		url := fmt.Sprintf("%s?limit=%d&offset=%d", f.BaseURL, limit, offset)
		entries, rawCount, total, err := f.fetchPage(ctx, url)
		if err != nil {
			return nil, err
		}

		allEntries = append(allEntries, entries...)
		if progressFn != nil {
			progressFn(len(allEntries), total)
		}

		// Stop when the API returns an empty page or we've passed the total.
		if rawCount == 0 || offset+limit >= total {
			break
		}

		offset += limit
		time.Sleep(200 * time.Millisecond) // rate limiting
	}

	return allEntries, nil
}

func (f *UbuntuFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	// Ubuntu API doesn't easily support date-based filtering; fetch all.
	return f.FetchAll(ctx, progressFn)
}

// fetchPage returns (entries, rawCVECount, totalResults, error).
func (f *UbuntuFetcher) fetchPage(ctx context.Context, url string) ([]DBEntry, int, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, 0, err
	}

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, 0, fmt.Errorf("ubuntu CVE API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result ubuntuCVEResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, 0, fmt.Errorf("decoding Ubuntu CVE response: %w", err)
	}

	var entries []DBEntry
	for _, cve := range result.CVEs {
		entries = append(entries, f.transformCVE(cve)...)
	}

	return entries, len(result.CVEs), result.Total, nil
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
