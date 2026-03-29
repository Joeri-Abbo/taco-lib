// Package types defines core domain types shared across the TACO ecosystem.
package types

// Severity represents the severity level of a vulnerability.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ParseSeverity converts a string to a Severity value.
func ParseSeverity(s string) Severity {
	switch s {
	case "LOW":
		return SeverityLow
	case "MEDIUM":
		return SeverityMedium
	case "HIGH":
		return SeverityHigh
	case "CRITICAL":
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}

// Vulnerability is a single CVE or advisory matched to a package.
type Vulnerability struct {
	ID             string   `json:"id"`
	Severity       Severity `json:"severity"`
	Package        string   `json:"package"`
	Ecosystem      string   `json:"ecosystem"`
	Installed      string   `json:"installed_version"`
	FixedIn        string   `json:"fixed_in,omitempty"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	References     []string `json:"references,omitempty"`
	Source         string   `json:"source,omitempty"`
	KnownExploited bool     `json:"known_exploited,omitempty"`
}
