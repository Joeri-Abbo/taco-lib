package vulndb

// MergeMultiSource merges entries from multiple sources using precedence rules.
//
// For the same CVE+Package combination:
//   - Higher-priority sources (distro-specific for their ecosystem, then GHSA, OSV, NVD) win
//   - CISA KEV entries enrich existing entries by setting KnownExploited=true
//   - Fields from lower-priority sources fill in blanks left by higher-priority ones
func MergeMultiSource(sourceEntries map[SourceName][]DBEntry) []DBEntry {
	type entryKey struct {
		id  string
		pkg string
	}

	// Collect CISA KEV IDs for enrichment.
	kevIDs := make(map[string]bool)
	if kevEntries, ok := sourceEntries[SourceCISAKEV]; ok {
		for _, e := range kevEntries {
			kevIDs[e.ID] = true
		}
	}

	// Index: key -> best entry so far, keyed by source priority.
	best := make(map[entryKey]DBEntry)
	bestPriority := make(map[entryKey]int)

	// Process sources in precedence order (highest priority first).
	for _, src := range AllSources {
		if src == SourceCISAKEV {
			continue // handled via enrichment
		}
		entries, ok := sourceEntries[src]
		if !ok {
			continue
		}
		priority := SourcePriority(src)

		for _, e := range entries {
			k := entryKey{id: e.ID, pkg: e.Package}
			existing, exists := best[k]
			if !exists {
				best[k] = e
				bestPriority[k] = priority
				continue
			}

			if priority < bestPriority[k] {
				// Higher priority source: replace but fill blanks from existing.
				merged := e
				if merged.Severity == "" || merged.Severity == "UNKNOWN" {
					merged.Severity = existing.Severity
				}
				if merged.Title == "" {
					merged.Title = existing.Title
				}
				if merged.Description == "" {
					merged.Description = existing.Description
				}
				if merged.FixedIn == "" {
					merged.FixedIn = existing.FixedIn
				}
				if len(merged.References) == 0 {
					merged.References = existing.References
				}
				if merged.CvssScore == 0 {
					merged.CvssScore = existing.CvssScore
				}
				best[k] = merged
				bestPriority[k] = priority
			} else {
				// Lower priority: fill in blanks on existing entry.
				if existing.Severity == "" || existing.Severity == "UNKNOWN" {
					existing.Severity = e.Severity
				}
				if existing.Title == "" {
					existing.Title = e.Title
				}
				if existing.Description == "" {
					existing.Description = e.Description
				}
				if existing.FixedIn == "" {
					existing.FixedIn = e.FixedIn
				}
				if len(existing.References) == 0 {
					existing.References = e.References
				}
				if existing.CvssScore == 0 {
					existing.CvssScore = e.CvssScore
				}
				best[k] = existing
			}
		}
	}

	// Enrich with CISA KEV.
	for k, e := range best {
		if kevIDs[e.ID] {
			e.KnownExploited = true
			best[k] = e
		}
	}

	result := make([]DBEntry, 0, len(best))
	for _, e := range best {
		result = append(result, e)
	}
	return result
}
