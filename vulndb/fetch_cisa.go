package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const cisaKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// CISAKEVFetcher downloads the CISA Known Exploited Vulnerabilities catalog.
// KEV entries don't create standalone vulnerability records; they enrich
// existing entries by marking them as known-exploited during merge.
type CISAKEVFetcher struct {
	HTTPClient *http.Client
	BaseURL    string
}

var _ SourceFetcher = (*CISAKEVFetcher)(nil)

func NewCISAKEVFetcher() *CISAKEVFetcher {
	return &CISAKEVFetcher{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		BaseURL:    cisaKEVURL,
	}
}

func (f *CISAKEVFetcher) Name() SourceName { return SourceCISAKEV }

type cisaKEVCatalog struct {
	Title           string        `json:"title"`
	CatalogVersion  string        `json:"catalogVersion"`
	DateReleased    string        `json:"dateReleased"`
	Count           int           `json:"count"`
	Vulnerabilities []cisaKEVVuln `json:"vulnerabilities"`
}

type cisaKEVVuln struct {
	CVEID              string `json:"cveID"`
	VendorProject      string `json:"vendorProject"`
	Product            string `json:"product"`
	VulnerabilityName  string `json:"vulnerabilityName"`
	DateAdded          string `json:"dateAdded"`
	ShortDescription   string `json:"shortDescription"`
	RequiredAction     string `json:"requiredAction"`
	DueDate            string `json:"dueDate"`
	KnownRansomware    string `json:"knownRansomwareCampaignUse"`
}

func (f *CISAKEVFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
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
		return nil, fmt.Errorf("CISA KEV returned status %d: %s", resp.StatusCode, string(body))
	}

	var catalog cisaKEVCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decoding CISA KEV catalog: %w", err)
	}

	entries := make([]DBEntry, 0, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		entries = append(entries, DBEntry{
			ID:             v.CVEID,
			Severity:       "CRITICAL", // all KEV entries are considered critical
			Title:          v.VulnerabilityName,
			Description:    v.ShortDescription,
			Source:         string(SourceCISAKEV),
			KnownExploited: true,
		})
	}

	if progressFn != nil {
		progressFn(len(entries), len(entries))
	}

	return entries, nil
}

func (f *CISAKEVFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	// KEV catalog is small; always fetch all.
	allEntries, err := f.FetchAll(ctx, progressFn)
	if err != nil {
		return nil, err
	}

	// Filter by dateAdded if days > 0.
	if days <= 0 {
		return allEntries, nil
	}

	// filtering would require storing dateAdded on DBEntry; return all for now.
	// The merge will handle dedup.
	return allEntries, nil
}

// KEVIDs returns a set of CVE IDs from a CISA KEV fetch result, for use in enrichment.
func KEVIDs(entries []DBEntry) map[string]bool {
	ids := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.Source == string(SourceCISAKEV) {
			ids[e.ID] = true
		}
	}
	return ids
}
