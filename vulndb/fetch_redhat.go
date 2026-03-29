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

const redhatAPIBaseURL = "https://access.redhat.com/hydra/rest/securitydata"

// RedHatFetcher downloads vulnerability data from the Red Hat Security Data API.
type RedHatFetcher struct {
	HTTPClient *http.Client
	BaseURL    string
}

var _ SourceFetcher = (*RedHatFetcher)(nil)

func NewRedHatFetcher() *RedHatFetcher {
	return &RedHatFetcher{
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
		BaseURL:    redhatAPIBaseURL,
	}
}

func (f *RedHatFetcher) Name() SourceName { return SourceRedHat }

type redhatCVEListItem struct {
	CVE             string      `json:"CVE"`
	Severity        string      `json:"severity"`
	PublicDate      string      `json:"public_date"`
	BugzillaDesc    string      `json:"bugzilla_description"`
	ResourceURL     string      `json:"resource_url"`
	CvssScore       json.Number `json:"cvss3_score"`
}

func (f *RedHatFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	return f.fetch(ctx, 0, progressFn)
}

func (f *RedHatFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	return f.fetch(ctx, days, progressFn)
}

func (f *RedHatFetcher) fetch(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	// First, get the CVE list.
	cveList, err := f.fetchCVEList(ctx, days)
	if err != nil {
		return nil, err
	}

	var allEntries []DBEntry
	total := len(cveList)

	for i, item := range cveList {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		entries := f.transformListItem(item)
		allEntries = append(allEntries, entries...)

		if progressFn != nil && (i+1)%100 == 0 {
			progressFn(i+1, total)
		}
	}

	if progressFn != nil {
		progressFn(total, total)
	}

	return allEntries, nil
}

func (f *RedHatFetcher) fetchCVEList(ctx context.Context, days int) ([]redhatCVEListItem, error) {
	var allItems []redhatCVEListItem
	page := 1

	for {
		url := fmt.Sprintf("%s/cve.json?per_page=500&page=%d", f.BaseURL, page)
		if days > 0 {
			after := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
			url += "&after=" + after
		}

		items, err := f.fetchCVEListPage(ctx, url)
		if err != nil {
			return nil, err
		}

		if len(items) == 0 {
			break
		}

		allItems = append(allItems, items...)
		page++

		time.Sleep(200 * time.Millisecond) // rate limiting
	}

	return allItems, nil
}

func (f *RedHatFetcher) fetchCVEListPage(ctx context.Context, url string) ([]redhatCVEListItem, error) {
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
		return nil, fmt.Errorf("red hat API returned status %d: %s", resp.StatusCode, string(body))
	}

	var items []redhatCVEListItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("decoding Red Hat CVE list: %w", err)
	}

	return items, nil
}

func (f *RedHatFetcher) transformListItem(item redhatCVEListItem) []DBEntry {
	severity := strings.ToUpper(item.Severity)
	switch severity {
	case "IMPORTANT":
		severity = "HIGH"
	case "MODERATE":
		severity = "MEDIUM"
	}

	// Red Hat CVE list items don't have per-package info in the list endpoint.
	// We create a single entry per CVE; detailed per-package info would require
	// fetching each CVE detail (too slow for bulk).
	return []DBEntry{
		{
			ID:               item.CVE,
			Severity:         severity,
			Ecosystem:        "rpm",
			Package:          "", // populated when detail is fetched
			AffectedVersions: "*",
			Title:            item.BugzillaDesc,
			References:       []string{item.ResourceURL},
			Source:           string(SourceRedHat),
		},
	}
}
