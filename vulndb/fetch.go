package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	nvdAPIBaseURL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdResultsPerPage = 500
	nvdRateLimit     = 6 * time.Second  // without API key
	nvdRateLimitKey  = 600 * time.Millisecond // with API key
)

// Fetcher downloads vulnerability data from the NVD API.
// It implements the SourceFetcher interface.
type Fetcher struct {
	HTTPClient *http.Client
	APIKey     string
	BaseURL    string
}

// Ensure Fetcher implements SourceFetcher.
var _ SourceFetcher = (*Fetcher)(nil)

// Name returns the source identifier.
func (f *Fetcher) Name() SourceName { return SourceNVD }

// NewFetcher creates a new NVD API fetcher.
func NewFetcher() *Fetcher {
	apiKey := os.Getenv("TACO_NVD_API_KEY")
	return &Fetcher{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		APIKey:     apiKey,
		BaseURL:    nvdAPIBaseURL,
	}
}

// nvdResponse is the top-level NVD API response.
type nvdResponse struct {
	ResultsPerPage int           `json:"resultsPerPage"`
	StartIndex     int           `json:"startIndex"`
	TotalResults   int           `json:"totalResults"`
	Vulnerabilities []nvdVulnItem `json:"vulnerabilities"`
}

type nvdVulnItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID               string            `json:"id"`
	Descriptions     []nvdDescription  `json:"descriptions"`
	Metrics          nvdMetrics        `json:"metrics"`
	Configurations   []nvdConfig       `json:"configurations"`
	References       []nvdReference    `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CvssMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CvssMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData struct {
		BaseSeverity string  `json:"baseSeverity"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type nvdCVSSMetricV2 struct {
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

type nvdReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// FetchAll downloads all CVEs from the NVD API and converts them to DBEntry format.
func (f *Fetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	var allEntries []DBEntry
	startIndex := 0

	rateLimit := nvdRateLimit
	if f.APIKey != "" {
		rateLimit = nvdRateLimitKey
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := f.fetchPage(ctx, startIndex)
		if err != nil {
			return nil, fmt.Errorf("fetching page at index %d: %w", startIndex, err)
		}

		entries := f.transformEntries(resp.Vulnerabilities)
		allEntries = append(allEntries, entries...)

		startIndex += resp.ResultsPerPage

		if progressFn != nil {
			progressFn(min(startIndex, resp.TotalResults), resp.TotalResults)
		}

		if startIndex >= resp.TotalResults {
			break
		}

		// Rate limiting
		time.Sleep(rateLimit)
	}

	return allEntries, nil
}

// FetchRecent downloads CVEs modified in the last N days.
func (f *Fetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	var allEntries []DBEntry
	startIndex := 0

	rateLimit := nvdRateLimit
	if f.APIKey != "" {
		rateLimit = nvdRateLimitKey
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		params := url.Values{}
		params.Set("startIndex", strconv.Itoa(startIndex))
		params.Set("resultsPerPage", strconv.Itoa(nvdResultsPerPage))

		now := time.Now().UTC()
		start := now.AddDate(0, 0, -days)
		params.Set("lastModStartDate", start.Format("2006-01-02T15:04:05.000"))
		params.Set("lastModEndDate", now.Format("2006-01-02T15:04:05.000"))

		reqURL := f.BaseURL + "?" + params.Encode()
		resp, err := f.doRequest(ctx, reqURL)
		if err != nil {
			return nil, fmt.Errorf("fetching recent CVEs at index %d: %w", startIndex, err)
		}

		entries := f.transformEntries(resp.Vulnerabilities)
		allEntries = append(allEntries, entries...)

		startIndex += resp.ResultsPerPage

		if progressFn != nil {
			progressFn(min(startIndex, resp.TotalResults), resp.TotalResults)
		}

		if startIndex >= resp.TotalResults {
			break
		}

		time.Sleep(rateLimit)
	}

	return allEntries, nil
}

func (f *Fetcher) fetchPage(ctx context.Context, startIndex int) (*nvdResponse, error) {
	params := url.Values{}
	params.Set("startIndex", strconv.Itoa(startIndex))
	params.Set("resultsPerPage", strconv.Itoa(nvdResultsPerPage))

	reqURL := f.BaseURL + "?" + params.Encode()
	return f.doRequest(ctx, reqURL)
}

func (f *Fetcher) doRequest(ctx context.Context, reqURL string) (*nvdResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	if f.APIKey != "" {
		req.Header.Set("apiKey", f.APIKey)
	}

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, string(body))
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decoding NVD response: %w", err)
	}

	return &nvdResp, nil
}

func (f *Fetcher) transformEntries(vulns []nvdVulnItem) []DBEntry {
	var entries []DBEntry

	for _, v := range vulns {
		severity := extractSeverity(v.CVE.Metrics)
		title := extractDescription(v.CVE.Descriptions, 120)
		description := extractDescription(v.CVE.Descriptions, 0)
		refs := extractReferences(v.CVE.References)

		// Extract affected packages from CPE configurations
		for _, config := range v.CVE.Configurations {
			for _, node := range config.Nodes {
				for _, match := range node.CPEMatch {
					if !match.Vulnerable {
						continue
					}

					ecosystem, pkg := parseCPE(match.Criteria)
					if ecosystem == "" || pkg == "" {
						continue
					}

					constraint := buildConstraint(match)
					fixedIn := match.VersionEndExcluding // the fix version

					entries = append(entries, DBEntry{
						ID:               v.CVE.ID,
						Severity:         severity,
						Ecosystem:        ecosystem,
						Package:          pkg,
						AffectedVersions: constraint,
						FixedIn:          fixedIn,
						Title:            title,
						Description:      description,
						References:       refs,
						Source:           string(SourceNVD),
					})
				}
			}
		}
	}

	return entries
}

func extractSeverity(metrics nvdMetrics) string {
	if len(metrics.CvssMetricV31) > 0 {
		return strings.ToUpper(metrics.CvssMetricV31[0].CVSSData.BaseSeverity)
	}
	if len(metrics.CvssMetricV30) > 0 {
		return strings.ToUpper(metrics.CvssMetricV30[0].CVSSData.BaseSeverity)
	}
	if len(metrics.CvssMetricV2) > 0 {
		return strings.ToUpper(metrics.CvssMetricV2[0].BaseSeverity)
	}
	return "UNKNOWN"
}

func extractDescription(descs []nvdDescription, maxLen int) string {
	for _, d := range descs {
		if d.Lang == "en" {
			if maxLen > 0 && len(d.Value) > maxLen {
				return d.Value[:maxLen] + "..."
			}
			return d.Value
		}
	}
	if len(descs) > 0 {
		if maxLen > 0 && len(descs[0].Value) > maxLen {
			return descs[0].Value[:maxLen] + "..."
		}
		return descs[0].Value
	}
	return ""
}

func extractReferences(refs []nvdReference) []string {
	var urls []string
	for _, r := range refs {
		urls = append(urls, r.URL)
	}
	return urls
}

// parseCPE extracts ecosystem and package name from a CPE 2.3 string.
// Format: cpe:2.3:a:vendor:product:version:...
func parseCPE(cpe string) (ecosystem, pkg string) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return "", ""
	}

	vendor := parts[3]
	product := parts[4]

	// Map common vendors to ecosystems
	switch vendor {
	case "nodejs", "npmjs":
		ecosystem = "npm"
	case "python", "pypi", "python-pillow":
		ecosystem = "pip"
	case "golang", "go":
		ecosystem = "go"
	case "debian":
		ecosystem = "debian"
	case "redhat", "fedoraproject":
		ecosystem = "rpm"
	case "alpine":
		ecosystem = "apk"
	default:
		ecosystem = vendor
	}

	return ecosystem, product
}

func buildConstraint(match nvdCPEMatch) string {
	var parts []string

	if match.VersionStartIncluding != "" {
		parts = append(parts, ">="+match.VersionStartIncluding)
	}
	if match.VersionStartExcluding != "" {
		parts = append(parts, ">"+match.VersionStartExcluding)
	}
	if match.VersionEndIncluding != "" {
		parts = append(parts, "<="+match.VersionEndIncluding)
	}
	if match.VersionEndExcluding != "" {
		parts = append(parts, "<"+match.VersionEndExcluding)
	}

	if len(parts) == 0 {
		// Extract version from CPE if available
		cpeParts := strings.Split(match.Criteria, ":")
		if len(cpeParts) >= 6 && cpeParts[5] != "*" && cpeParts[5] != "-" {
			return "=" + cpeParts[5]
		}
		return "*"
	}

	return strings.Join(parts, ",")
}

// NewSourceFetcherByName creates a SourceFetcher for the given source name.
func NewSourceFetcherByName(name SourceName) SourceFetcher {
	switch name {
	case SourceNVD:
		return NewFetcher()
	case SourceOSV:
		return NewOSVFetcher()
	case SourceGHSA:
		return NewGHSAFetcher()
	case SourceAlpine:
		return NewAlpineFetcher()
	case SourceDebian:
		return NewDebianFetcher()
	case SourceUbuntu:
		return NewUbuntuFetcher()
	case SourceRedHat:
		return NewRedHatFetcher()
	case SourceALAS:
		return NewALASFetcher()
	case SourceCISAKEV:
		return NewCISAKEVFetcher()
	default:
		return nil
	}
}

// NewAllFetchers creates fetchers for all default sources.
func NewAllFetchers() []SourceFetcher {
	sources := DefaultSources()
	fetchers := make([]SourceFetcher, 0, len(sources))
	for _, s := range sources {
		if f := NewSourceFetcherByName(s); f != nil {
			fetchers = append(fetchers, f)
		}
	}
	return fetchers
}

// NewFetchersForSources creates fetchers for the specified source names.
func NewFetchersForSources(names []SourceName) []SourceFetcher {
	fetchers := make([]SourceFetcher, 0, len(names))
	for _, name := range names {
		if f := NewSourceFetcherByName(name); f != nil {
			fetchers = append(fetchers, f)
		}
	}
	return fetchers
}

// MultiSourceProgressFn reports progress for a specific source.
type MultiSourceProgressFn func(source string, fetched, total int)

// UpdateOptions controls the behavior of UpdateMultiSource.
type UpdateOptions struct {
	// Full forces a full historical fetch (FetchAll) instead of incremental.
	Full bool
}

// Update fetches the latest vulnerability data and updates the cache.
// It accepts an optional list of sources; if nil, all default sources are used.
func Update(ctx context.Context, cache *Cache, progressFn func(fetched, total int)) error {
	return UpdateMultiSource(ctx, cache, nil, nil, func(source string, fetched, total int) {
		if progressFn != nil {
			progressFn(fetched, total)
		}
	})
}

// UpdateMultiSource fetches from multiple sources concurrently and merges results.
// If opts is nil, defaults are used (incremental if cache exists, 120-day seed otherwise).
func UpdateMultiSource(ctx context.Context, cache *Cache, sources []SourceFetcher, opts *UpdateOptions, progressFn MultiSourceProgressFn) error {
	if len(sources) == 0 {
		sources = NewAllFetchers()
	}
	if opts == nil {
		opts = &UpdateOptions{}
	}

	// Determine fetch strategy:
	//   --full flag  → always FetchAll (full historical data)
	//   cache exists → FetchRecent(7 days) incremental update
	//   no cache     → FetchAll (first-time seed with complete history)
	useFullFetch := opts.Full || !cache.Exists()

	// Fetch from all sources concurrently.
	type sourceResult struct {
		name    SourceName
		entries []DBEntry
		err     error
	}

	results := make(chan sourceResult, len(sources))
	for _, src := range sources {
		go func(s SourceFetcher) {
			srcProgressFn := func(fetched, total int) {
				if progressFn != nil {
					progressFn(string(s.Name()), fetched, total)
				}
			}

			var entries []DBEntry
			var err error
			if useFullFetch {
				entries, err = s.FetchAll(ctx, srcProgressFn)
			} else {
				entries, err = s.FetchRecent(ctx, 7, srcProgressFn)
			}
			results <- sourceResult{name: s.Name(), entries: entries, err: err}
		}(src)
	}

	// Collect results.
	sourceEntries := make(map[SourceName][]DBEntry)
	for range sources {
		r := <-results
		if r.err != nil {
			continue
		}
		sourceEntries[r.name] = r.entries
	}

	// Merge with existing cache if present.
	// Existing entries are added only for sources that were NOT freshly fetched,
	// so fresh data always takes priority over stale cached data.
	if cache.Exists() {
		existingDB, loadErr := NewFromFile(cache.DBPath())
		if loadErr == nil {
			existing := existingDB.(*jsonDB)
			for _, e := range existing.entries {
				src := SourceName(e.Source)
				if src == "" {
					src = SourceNVD // legacy entries without source field
				}
				// Only keep cached entries for sources we didn't just fetch.
				// For sources we did fetch, the fresh data replaces the cache.
				if _, fetched := sourceEntries[src]; !fetched {
					sourceEntries[src] = append(sourceEntries[src], e)
				}
			}
			_ = existingDB.Close()

			// For sources we did fetch fresh: merge fresh entries with cached
			// entries from the SAME source so we don't lose old CVEs not in
			// the recent window. Load cached per-source entries and let the
			// fresh ones overwrite by key.
			cachedBySource := make(map[SourceName][]DBEntry)
			for _, e := range existing.entries {
				src := SourceName(e.Source)
				if src == "" {
					src = SourceNVD
				}
				cachedBySource[src] = append(cachedBySource[src], e)
			}
			for src, freshEntries := range sourceEntries {
				if cached, ok := cachedBySource[src]; ok {
					// Put cached first, then fresh on top so fresh wins in mergeEntries.
					sourceEntries[src] = mergeEntries(cached, freshEntries)
				}
			}
		}
	}

	// Merge all sources with precedence.
	merged := MergeMultiSource(sourceEntries)

	if err := cache.WriteDB(merged); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}

	// Update per-source metadata.
	sourceMeta := make(map[string]SourceMeta)
	for src, entries := range sourceEntries {
		sourceMeta[string(src)] = SourceMeta{
			LastUpdated: time.Now(),
			EntryCount:  len(entries),
		}
	}
	meta, _ := cache.ReadMeta()
	if meta != nil {
		meta.Sources = sourceMeta
		_ = cache.WriteMeta(meta)
	}

	return nil
}

// mergeEntries merges new entries into existing entries, replacing entries with the same ID+package.
func mergeEntries(existing, new []DBEntry) []DBEntry {
	seen := make(map[string]int) // key: id+package -> index
	result := make([]DBEntry, len(existing))
	copy(result, existing)

	for i, e := range result {
		key := e.ID + "|" + e.Package
		seen[key] = i
	}

	for _, e := range new {
		key := e.ID + "|" + e.Package
		if idx, ok := seen[key]; ok {
			result[idx] = e // update existing
		} else {
			result = append(result, e)
			seen[key] = len(result) - 1
		}
	}

	return result
}
