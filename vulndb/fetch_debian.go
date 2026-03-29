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

const debianTrackerURL = "https://security-tracker.debian.org/tracker/data/json"

// DebianFetcher downloads vulnerability data from the Debian Security Tracker.
type DebianFetcher struct {
	HTTPClient *http.Client
	BaseURL    string
}

var _ SourceFetcher = (*DebianFetcher)(nil)

func NewDebianFetcher() *DebianFetcher {
	return &DebianFetcher{
		HTTPClient: &http.Client{Timeout: 120 * time.Second}, // large download
		BaseURL:    debianTrackerURL,
	}
}

func (f *DebianFetcher) Name() SourceName { return SourceDebian }

// debianTracker is the top-level structure: package -> CVE -> release info.
type debianTracker map[string]map[string]debianCVEInfo

type debianCVEInfo struct {
	Description string                      `json:"description"`
	Releases    map[string]debianReleaseInfo `json:"releases"`
	Scope       string                       `json:"scope"`
}

type debianReleaseInfo struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
}

// debianActiveReleases are the Debian releases we track.
var debianActiveReleases = map[string]bool{
	"bookworm": true, // Debian 12
	"trixie":   true, // Debian 13
	"sid":      true, // unstable
	"bullseye": true, // Debian 11
}

func (f *DebianFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.BaseURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("debian tracker returned status %d: %s", resp.StatusCode, string(body))
	}

	var tracker debianTracker
	if err := json.NewDecoder(resp.Body).Decode(&tracker); err != nil {
		return nil, fmt.Errorf("decoding Debian tracker JSON: %w", err)
	}

	var entries []DBEntry
	total := len(tracker)
	fetched := 0

	for pkgName, cves := range tracker {
		for cveID, info := range cves {
			if !strings.HasPrefix(cveID, "CVE-") {
				continue
			}

			for release, releaseInfo := range info.Releases {
				if !debianActiveReleases[release] {
					continue
				}

				if releaseInfo.Status == "not-affected" {
					continue
				}

				constraint := "*"
				fixedIn := ""
				if releaseInfo.FixedVersion != "" && releaseInfo.FixedVersion != "0" {
					constraint = "<" + releaseInfo.FixedVersion
					fixedIn = releaseInfo.FixedVersion
				}

				severity := debianUrgencyToSeverity(releaseInfo.Urgency)

				entries = append(entries, DBEntry{
					ID:               cveID,
					Severity:         severity,
					Ecosystem:        "debian",
					Package:          pkgName,
					AffectedVersions: constraint,
					FixedIn:          fixedIn,
					Title:            fmt.Sprintf("%s in %s", cveID, pkgName),
					Description:      truncate(info.Description, 500),
					Source:           string(SourceDebian),
				})
			}
		}
		fetched++
		if progressFn != nil && fetched%1000 == 0 {
			progressFn(fetched, total)
		}
	}

	if progressFn != nil {
		progressFn(fetched, total)
	}

	return entries, nil
}

func (f *DebianFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	// Debian tracker doesn't support incremental; fetch all.
	return f.FetchAll(ctx, progressFn)
}

func debianUrgencyToSeverity(urgency string) string {
	urgency = strings.Split(urgency, " ")[0] // strip annotations like "low**"
	switch strings.TrimRight(urgency, "*") {
	case "unimportant", "negligible":
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
