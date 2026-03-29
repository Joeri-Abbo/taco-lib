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

const alasBaseURL = "https://alas.aws.amazon.com"

// ALASFetcher downloads vulnerability data from Amazon Linux Security Advisories.
type ALASFetcher struct {
	HTTPClient *http.Client
	BaseURL    string
}

var _ SourceFetcher = (*ALASFetcher)(nil)

func NewALASFetcher() *ALASFetcher {
	return &ALASFetcher{
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
		BaseURL:    alasBaseURL,
	}
}

func (f *ALASFetcher) Name() SourceName { return SourceALAS }

// alasVersions are the Amazon Linux versions to fetch.
var alasVersions = []struct {
	name    string
	feedURL string
}{
	{"AL2", "/AL2/alas.json"},
	{"AL2023", "/AL2023/alas.json"},
}

type alasFeed struct {
	Advisories []alasAdvisory `json:"advisories"`
}

type alasAdvisory struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CVEs        []string `json:"cves"`
	Packages    []alasPkg `json:"packages"`
	References  []string `json:"references"`
	IssuedDate  string   `json:"issued_date"`
}

type alasPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Release string `json:"release"`
	Arch    string `json:"arch"`
}

func (f *ALASFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	var allEntries []DBEntry

	for i, ver := range alasVersions {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		entries, err := f.fetchVersion(ctx, ver.name, ver.feedURL)
		if err != nil {
			// If feed doesn't exist or format is different, skip.
			continue
		}
		allEntries = append(allEntries, entries...)

		if progressFn != nil {
			progressFn(i+1, len(alasVersions))
		}
	}

	return allEntries, nil
}

func (f *ALASFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	// ALAS doesn't support incremental; fetch all.
	return f.FetchAll(ctx, progressFn)
}

func (f *ALASFetcher) fetchVersion(ctx context.Context, version, feedPath string) ([]DBEntry, error) {
	url := f.BaseURL + feedPath

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
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ALAS API returned status %d for %s: %s", resp.StatusCode, version, string(body))
	}

	var feed alasFeed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, fmt.Errorf("decoding ALAS feed for %s: %w", version, err)
	}

	var entries []DBEntry
	for _, adv := range feed.Advisories {
		entries = append(entries, f.transformAdvisory(adv, version)...)
	}

	return entries, nil
}

func (f *ALASFetcher) transformAdvisory(adv alasAdvisory, version string) []DBEntry {
	var entries []DBEntry

	severity := strings.ToUpper(adv.Severity)
	switch severity {
	case "IMPORTANT":
		severity = "HIGH"
	case "MODERATE":
		severity = "MEDIUM"
	}

	description := adv.Description
	if len(description) > 500 {
		description = description[:500] + "..."
	}

	// Create one entry per CVE per package.
	cves := adv.CVEs
	if len(cves) == 0 {
		cves = []string{adv.ID}
	}

	for _, pkg := range adv.Packages {
		fixedVersion := pkg.Version
		if pkg.Release != "" {
			fixedVersion += "-" + pkg.Release
		}

		for _, cve := range cves {
			entries = append(entries, DBEntry{
				ID:               cve,
				Severity:         severity,
				Ecosystem:        "amazonlinux",
				Package:          pkg.Name,
				AffectedVersions: "<" + fixedVersion,
				FixedIn:          fixedVersion,
				Title:            adv.Title,
				Description:      description,
				References:       adv.References,
				Source:           string(SourceALAS),
			})
		}
	}

	return entries
}
