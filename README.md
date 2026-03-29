# taco-lib

Shared Go library for the TACO vulnerability scanner ecosystem.

## Packages

- `types` — Core domain types (Severity, Vulnerability)
- `vulndb` — Vulnerability database: fetching, caching, matching, OCI distribution, HTTP serving

## Usage

```go
import (
    "github.com/Joeri-Abbo/taco-lib/types"
    "github.com/Joeri-Abbo/taco-lib/vulndb"
)
```
