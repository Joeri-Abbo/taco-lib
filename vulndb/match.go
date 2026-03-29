package vulndb

import (
	"fmt"
	"strconv"
	"strings"
)

// VersionMatches checks if an installed version matches an affected version constraint.
// Supported constraint formats:
//   - "<1.2.3"       — less than
//   - "<=1.2.3"      — less than or equal
//   - ">=1.0.0,<1.2.3" — range (all conditions must match)
//   - "=1.2.3"       — exact match
//   - "*"            — all versions
func VersionMatches(installed, constraint string) (bool, error) {
	if constraint == "*" || constraint == "" {
		return true, nil
	}

	// Split on comma for range constraints
	parts := strings.Split(constraint, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		matched, err := matchSingle(installed, part)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

func matchSingle(installed, constraint string) (bool, error) {
	if strings.HasPrefix(constraint, "<=") {
		target := strings.TrimPrefix(constraint, "<=")
		cmp, err := compareVersions(installed, strings.TrimSpace(target))
		if err != nil {
			return false, err
		}
		return cmp <= 0, nil
	}
	if strings.HasPrefix(constraint, ">=") {
		target := strings.TrimPrefix(constraint, ">=")
		cmp, err := compareVersions(installed, strings.TrimSpace(target))
		if err != nil {
			return false, err
		}
		return cmp >= 0, nil
	}
	if strings.HasPrefix(constraint, "<") {
		target := strings.TrimPrefix(constraint, "<")
		cmp, err := compareVersions(installed, strings.TrimSpace(target))
		if err != nil {
			return false, err
		}
		return cmp < 0, nil
	}
	if strings.HasPrefix(constraint, ">") {
		target := strings.TrimPrefix(constraint, ">")
		cmp, err := compareVersions(installed, strings.TrimSpace(target))
		if err != nil {
			return false, err
		}
		return cmp > 0, nil
	}
	if strings.HasPrefix(constraint, "=") {
		target := strings.TrimPrefix(constraint, "=")
		cmp, err := compareVersions(installed, strings.TrimSpace(target))
		if err != nil {
			return false, err
		}
		return cmp == 0, nil
	}

	// Default: treat as exact match
	cmp, err := compareVersions(installed, constraint)
	if err != nil {
		return false, err
	}
	return cmp == 0, nil
}

// compareVersions compares two version strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Handles semver-like versions (1.2.3) and epoch:version-revision (debian).
func compareVersions(a, b string) (int, error) {
	// Strip leading 'v' prefix
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	// Handle epoch (debian-style "1:2.3.4")
	aEpoch, aVer := splitEpoch(a)
	bEpoch, bVer := splitEpoch(b)

	if aEpoch != bEpoch {
		if aEpoch < bEpoch {
			return -1, nil
		}
		return 1, nil
	}

	// Split on '-' to separate version from revision (e.g., "1.2.3-4")
	aMain, aRev := splitRevision(aVer)
	bMain, bRev := splitRevision(bVer)

	cmp, err := compareSegments(aMain, bMain)
	if err != nil {
		return 0, err
	}
	if cmp != 0 {
		return cmp, nil
	}

	// Compare revisions
	return compareSegments(aRev, bRev)
}

func splitEpoch(v string) (int, string) {
	if idx := strings.Index(v, ":"); idx != -1 {
		epoch, err := strconv.Atoi(v[:idx])
		if err == nil {
			return epoch, v[idx+1:]
		}
	}
	return 0, v
}

func splitRevision(v string) (string, string) {
	if idx := strings.LastIndex(v, "-"); idx != -1 {
		return v[:idx], v[idx+1:]
	}
	return v, "0"
}

func compareSegments(a, b string) (int, error) {
	if a == "" && b == "" {
		return 0, nil
	}

	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var aVal, bVal string
		if i < len(aParts) {
			aVal = aParts[i]
		}
		if i < len(bParts) {
			bVal = bParts[i]
		}

		// Try numeric comparison first
		aNum, aErr := strconv.Atoi(aVal)
		bNum, bErr := strconv.Atoi(bVal)

		if aErr == nil && bErr == nil {
			if aNum < bNum {
				return -1, nil
			}
			if aNum > bNum {
				return 1, nil
			}
			continue
		}

		// Fall back to string comparison for pre-release tags etc.
		if aVal == "" && bVal != "" {
			return -1, nil
		}
		if aVal != "" && bVal == "" {
			return 1, nil
		}

		// Alphanumeric comparison
		cmp := compareAlphanumeric(aVal, bVal)
		if cmp != 0 {
			return cmp, nil
		}
	}

	return 0, nil
}

func compareAlphanumeric(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// CompareVersions is exported for use by other packages.
func CompareVersions(a, b string) (int, error) {
	return compareVersions(a, b)
}

// IsVersionLessThan returns true if version a is less than version b.
func IsVersionLessThan(a, b string) (bool, error) {
	cmp, err := compareVersions(a, b)
	if err != nil {
		return false, fmt.Errorf("comparing versions %s and %s: %w", a, b, err)
	}
	return cmp < 0, nil
}
