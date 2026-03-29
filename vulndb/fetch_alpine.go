package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const alpineSecDBBaseURL = "https://secdb.alpinelinux.org"

// AlpineFetcher downloads vulnerability data from Alpine Linux SecDB.
type AlpineFetcher struct {
	HTTPClient *http.Client
	BaseURL    string
}

var _ SourceFetcher = (*AlpineFetcher)(nil)

func NewAlpineFetcher() *AlpineFetcher {
	return &AlpineFetcher{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		BaseURL:    alpineSecDBBaseURL,
	}
}

func (f *AlpineFetcher) Name() SourceName { return SourceAlpine }

// alpineBranches lists the Alpine branches to fetch.
var alpineBranches = []string{"v3.17", "v3.18", "v3.19", "v3.20", "edge"}
var alpineRepos = []string{"main", "community"}

type alpineSecDB struct {
	DistroVersion string       `json:"distroversion"`
	RepoName      string       `json:"reponame"`
	Packages      []alpinePkg  `json:"packages"`
}

type alpinePkg struct {
	Pkg alpinePkgDetail `json:"pkg"`
}

type alpinePkgDetail struct {
	Name     string              `json:"name"`
	Secfixes map[string][]string `json:"secfixes"` // version -> []CVE-ID
}

func (f *AlpineFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	type branchRepoResult struct {
		entries []DBEntry
		err     error
	}

	total := len(alpineBranches) * len(alpineRepos)
	results := make(chan branchRepoResult, total)

	for _, branch := range alpineBranches {
		for _, repo := range alpineRepos {
			go func(b, r string) {
				entries, err := f.fetchBranchRepo(ctx, b, r)
				results <- branchRepoResult{entries: entries, err: err}
			}(branch, repo)
		}
	}

	var allEntries []DBEntry
	fetched := 0
	for range total {
		r := <-results
		fetched++
		if r.err != nil {
			// Some branch/repo combos may not exist; skip.
			continue
		}
		allEntries = append(allEntries, r.entries...)
		if progressFn != nil {
			progressFn(fetched, total)
		}
	}

	return allEntries, nil
}

func (f *AlpineFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	// Alpine SecDB doesn't support incremental; fetch all.
	return f.FetchAll(ctx, progressFn)
}

func (f *AlpineFetcher) fetchBranchRepo(ctx context.Context, branch, repo string) ([]DBEntry, error) {
	url := fmt.Sprintf("%s/%s/%s.json", f.BaseURL, branch, repo)

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
		return nil, fmt.Errorf("alpine SecDB returned status %d for %s/%s: %s", resp.StatusCode, branch, repo, string(body))
	}

	var secdb alpineSecDB
	if err := json.NewDecoder(resp.Body).Decode(&secdb); err != nil {
		return nil, fmt.Errorf("decoding Alpine SecDB %s/%s: %w", branch, repo, err)
	}

	var entries []DBEntry
	for _, pkg := range secdb.Packages {
		for fixedVersion, cves := range pkg.Pkg.Secfixes {
			for _, cve := range cves {
				entries = append(entries, DBEntry{
					ID:               cve,
					Severity:         "UNKNOWN", // Alpine SecDB doesn't include severity
					Ecosystem:        "apk",
					Package:          pkg.Pkg.Name,
					AffectedVersions: "<" + fixedVersion,
					FixedIn:          fixedVersion,
					Title:            fmt.Sprintf("%s in %s", cve, pkg.Pkg.Name),
					Description:      fmt.Sprintf("Fixed in %s %s (%s/%s)", pkg.Pkg.Name, fixedVersion, branch, repo),
					Source:           string(SourceAlpine),
				})
			}
		}
	}

	return entries, nil
}
