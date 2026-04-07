# taco-lib

Shared Go library for the **TACO** vulnerability scanner ecosystem. It provides everything needed to fetch, cache, match, merge, distribute, and serve vulnerability data from multiple upstream sources.

## Features

- **Multi-source vulnerability fetching** — pulls CVE data from 9 sources, each with its own fetcher:
  - NVD (NIST National Vulnerability Database)
  - OSV (Open Source Vulnerabilities)
  - GHSA (GitHub Security Advisories)
  - Alpine SecDB
  - Debian Security Tracker
  - Ubuntu CVE Tracker
  - Red Hat Security Data
  - Amazon Linux (ALAS)
  - CISA Known Exploited Vulnerabilities (KEV)
- **Smart merging with source precedence** — distro-specific sources take priority for their ecosystem; CISA KEV enriches entries with `known_exploited` flags; lower-priority sources fill in missing fields.
- **Version matching engine** — supports semver-like comparisons, Debian epoch:version-revision format, and range constraints (`<1.2.3`, `>=1.0.0,<2.0.0`, exact match, wildcard).
- **Local caching** — JSON-file-backed database stored in `~/.taco/db` with staleness detection, per-source storage, and atomic writes.
- **Incremental updates** — fetches only recent changes (last 7 days) when a cache already exists; falls back to full historical fetch on first run or with the `--full` flag.
- **OCI distribution** — push and pull the vulnerability database as an OCI artifact to any container registry (e.g. `ghcr.io`), using `go-containerregistry`.
- **HTTP server** — lightweight server that hosts the database for other TACO instances, with endpoints for JSON, gzip, metadata, and health checks.
- **Database download and export** — download a pre-built database from a URL, load from a local file, or build a standalone database file for CI/CD pipelines. Supports gzip compression.

## Packages

| Package | Description |
|---------|-------------|
| `types` | Core domain types: `Severity` (Unknown/Low/Medium/High/Critical) and `Vulnerability` struct |
| `vulndb` | Vulnerability database: fetching, caching, matching, merging, OCI distribution, HTTP serving, and download/export utilities |

## Installation

```bash
go get github.com/Joeri-Abbo/taco-lib@latest
```

Requires **Go 1.25.7** or later.

## Usage

### Import

```go
import (
    "github.com/Joeri-Abbo/taco-lib/types"
    "github.com/Joeri-Abbo/taco-lib/vulndb"
)
```

### Load and query the database

```go
// Load from a JSON file
db, err := vulndb.NewFromFile("path/to/vulndb.json")
if err != nil {
    log.Fatal(err)
}
defer db.Close()

// Look up vulnerabilities for a specific package
vulns, err := db.Lookup("npm", "lodash", "4.17.20")
if err != nil {
    log.Fatal(err)
}

for _, v := range vulns {
    fmt.Printf("%s [%s] %s — fixed in %s\n", v.ID, v.Severity, v.Title, v.FixedIn)
}
```

### Update the local cache

```go
cache, err := vulndb.NewCache()
if err != nil {
    log.Fatal(err)
}

// Update from all default sources
err = vulndb.Update(context.Background(), cache, func(fetched, total int) {
    fmt.Printf("\r  %d / %d", fetched, total)
})
```

### Multi-source update with selected sources

```go
sources := vulndb.NewFetchersForSources([]vulndb.SourceName{
    vulndb.SourceNVD,
    vulndb.SourceGHSA,
    vulndb.SourceDebian,
})

err = vulndb.UpdateMultiSource(ctx, cache, sources, nil, func(source string, fetched, total int) {
    fmt.Printf("[%s] %d/%d\n", source, fetched, total)
})
```

### OCI distribution

```go
// Push database to a container registry
err = vulndb.PushOCI(cache, "ghcr.io/myorg/taco-vulndb:latest")

// Pull database from a container registry
err = vulndb.PullOCI(cache, "ghcr.io/myorg/taco-vulndb:latest")
```

### Serve the database over HTTP

```go
err = vulndb.Serve(ctx, vulndb.ServeOptions{
    Addr:  ":8080",
    Cache: cache,
})
// Endpoints:
//   GET /vulndb.json     — download database (JSON)
//   GET /vulndb.json.gz  — download database (gzip)
//   GET /meta.json       — database metadata
//   GET /health          — health check
```

### Version comparison utilities

```go
matched, err := vulndb.VersionMatches("1.2.3", ">=1.0.0,<2.0.0") // true
lessThan, err := vulndb.IsVersionLessThan("1.2.3", "1.3.0")       // true
cmp, err := vulndb.CompareVersions("2.0.0", "1.9.9")              // 1
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TACO_NVD_API_KEY` | NVD API key for higher rate limits (0.6s vs 6s between requests) |

## Tech Stack

- **Language:** Go 1.25+
- **Key dependency:** [go-containerregistry](https://github.com/google/go-containerregistry) for OCI push/pull
- **CI:** GitHub Actions with `go vet`, `go test -race`, and `golangci-lint`
- **Tested on:** Go 1.25.x and 1.26.x

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes and add tests
4. Run checks locally:
   ```bash
   go vet ./...
   go test -race ./...
   ```
5. Commit and push your branch
6. Open a pull request against `main`

## License

See the repository for license details.
