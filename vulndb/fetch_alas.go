package vulndb

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ALASFetcher downloads vulnerability data from Amazon Linux Security Advisories
// via the YUM repository updateinfo.xml metadata.
type ALASFetcher struct {
	HTTPClient *http.Client
}

var _ SourceFetcher = (*ALASFetcher)(nil)

func NewALASFetcher() *ALASFetcher {
	return &ALASFetcher{
		HTTPClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (f *ALASFetcher) Name() SourceName { return SourceALAS }

// alasRepos are the Amazon Linux YUM repo updateinfo URLs.
var alasRepos = []struct {
	name string
	url  string
}{
	{"AL2", "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"},
	{"AL2023", "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"},
}

// updateInfo is the XML structure of YUM updateinfo.xml.
type updateInfo struct {
	Updates []updateInfoUpdate `xml:"update"`
}

type updateInfoUpdate struct {
	Type        string                  `xml:"type,attr"`
	ID          string                  `xml:"id"`
	Title       string                  `xml:"title"`
	Severity    string                  `xml:"severity"`
	Description string                  `xml:"description"`
	References  updateInfoRefs          `xml:"references"`
	Packages    updateInfoPackageList   `xml:"pkglist"`
}

type updateInfoRefs struct {
	Refs []updateInfoRef `xml:"reference"`
}

type updateInfoRef struct {
	Type  string `xml:"type,attr"`
	Href  string `xml:"href,attr"`
	ID    string `xml:"id,attr"`
	Title string `xml:"title,attr"`
}

type updateInfoPackageList struct {
	Collections []updateInfoCollection `xml:"collection"`
}

type updateInfoCollection struct {
	Packages []updateInfoPkg `xml:"package"`
}

type updateInfoPkg struct {
	Name    string `xml:"name,attr"`
	Version string `xml:"version,attr"`
	Release string `xml:"release,attr"`
	Arch    string `xml:"arch,attr"`
	Epoch   string `xml:"epoch,attr"`
}

func (f *ALASFetcher) FetchAll(ctx context.Context, progressFn func(fetched, total int)) ([]DBEntry, error) {
	var allEntries []DBEntry

	for i, repo := range alasRepos {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		entries, err := f.fetchFromRepo(ctx, repo.name, repo.url)
		if err != nil {
			// Try direct updateinfo URL as fallback.
			continue
		}
		allEntries = append(allEntries, entries...)

		if progressFn != nil {
			progressFn(i+1, len(alasRepos))
		}
	}

	return allEntries, nil
}

func (f *ALASFetcher) FetchRecent(ctx context.Context, days int, progressFn func(fetched, total int)) ([]DBEntry, error) {
	return f.FetchAll(ctx, progressFn)
}

func (f *ALASFetcher) fetchFromRepo(ctx context.Context, repoName, mirrorListURL string) ([]DBEntry, error) {
	// Step 1: Get mirror list to find the base URL.
	baseURL, err := f.getMirrorBase(ctx, mirrorListURL)
	if err != nil {
		return nil, fmt.Errorf("getting mirror for %s: %w", repoName, err)
	}

	// Step 2: Fetch repomd.xml to find updateinfo location.
	updateInfoURL, err := f.findUpdateInfoURL(ctx, baseURL)
	if err != nil {
		return nil, fmt.Errorf("finding updateinfo for %s: %w", repoName, err)
	}

	// Step 3: Download and parse updateinfo.xml.gz.
	updates, err := f.fetchUpdateInfo(ctx, updateInfoURL)
	if err != nil {
		return nil, fmt.Errorf("fetching updateinfo for %s: %w", repoName, err)
	}

	// Step 4: Transform to DBEntry.
	var entries []DBEntry
	for _, u := range updates.Updates {
		if u.Type != "security" {
			continue
		}
		entries = append(entries, transformALASUpdate(u)...)
	}

	return entries, nil
}

func (f *ALASFetcher) getMirrorBase(ctx context.Context, mirrorListURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mirrorListURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Mirror list contains one URL per line; use the first.
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasPrefix(line, "http") {
			return strings.TrimRight(line, "/"), nil
		}
	}

	return "", fmt.Errorf("no mirror URL found in %s", mirrorListURL)
}

// repomd is the XML structure of repodata/repomd.xml.
type repomd struct {
	Data []repomdData `xml:"data"`
}

type repomdData struct {
	Type     string         `xml:"type,attr"`
	Location repomdLocation `xml:"location"`
}

type repomdLocation struct {
	Href string `xml:"href,attr"`
}

func (f *ALASFetcher) findUpdateInfoURL(ctx context.Context, baseURL string) (string, error) {
	repomdURL := baseURL + "/repodata/repomd.xml"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repomdURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("repomd.xml returned %d", resp.StatusCode)
	}

	var md repomd
	if err := xml.NewDecoder(resp.Body).Decode(&md); err != nil {
		return "", fmt.Errorf("parsing repomd.xml: %w", err)
	}

	for _, d := range md.Data {
		if d.Type == "updateinfo" {
			return baseURL + "/" + d.Location.Href, nil
		}
	}

	return "", fmt.Errorf("no updateinfo found in repomd.xml")
}

func (f *ALASFetcher) fetchUpdateInfo(ctx context.Context, url string) (*updateInfo, error) {
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
		return nil, fmt.Errorf("updateinfo returned %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	// updateinfo is typically gzip-compressed.
	if strings.HasSuffix(url, ".gz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("decompressing updateinfo: %w", err)
		}
		defer func() { _ = gz.Close() }()
		reader = gz
	}

	var info updateInfo
	if err := xml.NewDecoder(reader).Decode(&info); err != nil {
		return nil, fmt.Errorf("parsing updateinfo XML: %w", err)
	}

	return &info, nil
}

func transformALASUpdate(u updateInfoUpdate) []DBEntry {
	var entries []DBEntry

	severity := strings.ToUpper(u.Severity)
	switch severity {
	case "IMPORTANT":
		severity = "HIGH"
	case "MODERATE":
		severity = "MEDIUM"
	}

	description := u.Description
	if len(description) > 500 {
		description = description[:500] + "..."
	}

	// Collect CVE IDs from references.
	var cves []string
	var refs []string
	for _, r := range u.References.Refs {
		if r.Href != "" {
			refs = append(refs, r.Href)
		}
		if r.Type == "cve" {
			cves = append(cves, r.ID)
		}
	}
	if len(cves) == 0 {
		cves = []string{u.ID}
	}

	for _, col := range u.Packages.Collections {
		for _, pkg := range col.Packages {
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
					Title:            u.Title,
					Description:      description,
					References:       refs,
					Source:           string(SourceALAS),
				})
			}
		}
	}

	return entries
}
