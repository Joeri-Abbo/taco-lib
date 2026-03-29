package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const ghsaAPIBaseURL = "https://api.github.com/advisories"

// GHSAFetcher downloads vulnerability data from the GitHub Advisory Database.
type GHSAFetcher struct {
	HTTPClient *http.Client
	Token      string
	BaseURL    string
}

var _ SourceFetcher = (*GHSAFetcher)(nil)

func NewGHSAFetcher() *GHSAFetcher {
	token := os.Getenv("GITHUB_TOKEN")
	return &GHSAFetcher{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Token:      token,
		BaseURL:    ghsaAPIBaseURL,
	}
}

func (f *GHSAFetcher) Name() SourceName { return SourceGHSA }

// ghsaAdvisory represents a GitHub security advisory from the REST API.
type ghsaAdvisory struct {
	GHSAID          string              `json:"ghsa_id"`
	CVEID           string              `json:"cve_id"`
	Severity        string              `json:"severity"`
	Summary         string              `json:"summary"`
	Description     string              `json:"description"`
	Vulnerabilities []ghsaVulnerability `json:"vulnerabilities"`
	References      []string            `json:"references"`
	HTMLURL         string              `json:"html_url"`
	UpdatedAt       string              `json:"updated_at"`
}

type ghsaVulnerability struct {
	Package               ghsaPackage `json:"package"`
	VulnerableVersionRange string     `json:"vulnerable_version_range"`
	FirstPatchedVersion    *struct {
		Identifier string `json:"identifier"`
	} `json:"first_patched_version"`
}

type ghsaPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// ghsaEcosystemMap maps GitHub ecosystem names to TACO ecosystem names.
var ghsaEcosystemMap = map[string]string{
	"npm":       "npm",
	"pip":       "pip",
	"go":        "go",
	"maven":     "maven",
	"nuget":     "nuget",
	"rubygems":  "gem",
	"rust":      "cargo",
	"composer":  "composer",
	"pub":       "pub",
	"hex":       "hex",
	"swift":     "swift",
	"actions":   "actions",
}

func (f *GHSAFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	return f.fetch(ctx, "", progressFn)
}

func (f *GHSAFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	since := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02T15:04:05Z")
	return f.fetch(ctx, since, progressFn)
}

type ghsaPageResult struct {
	advisories []ghsaAdvisory
	nextCursor string
}

func (f *GHSAFetcher) fetch(ctx context.Context, since string, progressFn func(fetched, total int)) ([]DBEntry, error) {
	var allEntries []DBEntry
	cursor := ""

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		result, err := f.fetchPage(ctx, since, cursor)
		if err != nil {
			return nil, err
		}

		if len(result.advisories) == 0 {
			break
		}

		for _, adv := range result.advisories {
			entries := f.transformAdvisory(adv)
			allEntries = append(allEntries, entries...)
		}

		if progressFn != nil {
			progressFn(len(allEntries), 0)
		}

		if result.nextCursor == "" {
			break
		}
		cursor = result.nextCursor

		// Respect rate limiting.
		time.Sleep(100 * time.Millisecond)
	}

	return allEntries, nil
}

func (f *GHSAFetcher) fetchPage(ctx context.Context, since, cursor string) (*ghsaPageResult, error) {
	reqURL := f.BaseURL + "?per_page=100&type=reviewed"
	if since != "" {
		reqURL += "&updated=" + since
	}
	if cursor != "" {
		reqURL += "&after=" + cursor
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}

	resp, err := doWithRetry(f.HTTPClient, req, 3)
	if err != nil {
		return nil, fmt.Errorf("GitHub API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	var advisories []ghsaAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return nil, fmt.Errorf("decoding GHSA response: %w", err)
	}

	linkHeader := resp.Header.Get("Link")
	nextCursor := parseGHSANextCursor(linkHeader)

	return &ghsaPageResult{advisories: advisories, nextCursor: nextCursor}, nil
}

func (f *GHSAFetcher) transformAdvisory(adv ghsaAdvisory) []DBEntry {
	var entries []DBEntry

	id := adv.CVEID
	if id == "" {
		id = adv.GHSAID
	}

	severity := strings.ToUpper(adv.Severity)

	refs := make([]string, 0, len(adv.References)+1)
	if adv.HTMLURL != "" {
		refs = append(refs, adv.HTMLURL)
	}
	refs = append(refs, adv.References...)

	description := adv.Description
	if len(description) > 500 {
		description = description[:500] + "..."
	}

	for _, vuln := range adv.Vulnerabilities {
		eco, ok := ghsaEcosystemMap[strings.ToLower(vuln.Package.Ecosystem)]
		if !ok {
			continue
		}

		constraint := ghsaConvertRange(vuln.VulnerableVersionRange)
		fixedIn := ""
		if vuln.FirstPatchedVersion != nil {
			fixedIn = vuln.FirstPatchedVersion.Identifier
		}

		entries = append(entries, DBEntry{
			ID:               id,
			Severity:         severity,
			Ecosystem:        eco,
			Package:          vuln.Package.Name,
			AffectedVersions: constraint,
			FixedIn:          fixedIn,
			Title:            adv.Summary,
			Description:      description,
			References:       refs,
			Source:           string(SourceGHSA),
		})
	}

	return entries
}

// ghsaConvertRange converts GitHub's version range format to TACO constraint format.
// GitHub uses: ">= 1.0.0, < 1.2.3" or "= 1.0.0" or "< 2.0.0"
func ghsaConvertRange(r string) string {
	if r == "" {
		return "*"
	}
	// GitHub format is already close to ours; normalize spacing.
	parts := strings.Split(r, ",")
	var normalized []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Ensure no space between operator and version.
		p = strings.ReplaceAll(p, ">= ", ">=")
		p = strings.ReplaceAll(p, "<= ", "<=")
		p = strings.ReplaceAll(p, "> ", ">")
		p = strings.ReplaceAll(p, "< ", "<")
		p = strings.ReplaceAll(p, "= ", "=")
		normalized = append(normalized, p)
	}
	return strings.Join(normalized, ",")
}

// parseGHSANextCursor extracts the cursor from the GitHub Link header.
func parseGHSANextCursor(link string) string {
	if link == "" {
		return ""
	}
	// Link: <url?after=CURSOR>; rel="next", ...
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, `rel="next"`) {
			// Extract URL between < and >
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start >= 0 && end > start {
				url := part[start+1 : end]
				// Extract after= parameter
				if idx := strings.Index(url, "after="); idx >= 0 {
					cursor := url[idx+6:]
					if ampIdx := strings.Index(cursor, "&"); ampIdx >= 0 {
						cursor = cursor[:ampIdx]
					}
					return cursor
				}
			}
		}
	}
	return ""
}
