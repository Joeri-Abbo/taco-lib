package vulndb

import "testing"

func TestSourcePriority(t *testing.T) {
	// Alpine should have highest priority (lowest number)
	alpinePriority := SourcePriority(SourceAlpine)
	nvdPriority := SourcePriority(SourceNVD)

	if alpinePriority >= nvdPriority {
		t.Errorf("expected Alpine (%d) to have higher priority (lower number) than NVD (%d)", alpinePriority, nvdPriority)
	}

	// GHSA should have higher priority than NVD but lower than distro sources
	ghsaPriority := SourcePriority(SourceGHSA)
	debianPriority := SourcePriority(SourceDebian)

	if ghsaPriority <= debianPriority {
		t.Errorf("expected GHSA (%d) to have lower priority than Debian (%d)", ghsaPriority, debianPriority)
	}
	if ghsaPriority >= nvdPriority {
		t.Errorf("expected GHSA (%d) to have higher priority than NVD (%d)", ghsaPriority, nvdPriority)
	}
}

func TestSourcePriority_Unknown(t *testing.T) {
	priority := SourcePriority(SourceName("unknown-source"))
	if priority != len(AllSources) {
		t.Errorf("expected unknown source priority %d, got %d", len(AllSources), priority)
	}
}

func TestDefaultSources(t *testing.T) {
	sources := DefaultSources()
	if len(sources) != 9 {
		t.Errorf("expected 9 default sources, got %d", len(sources))
	}

	// Check all known sources are included
	expected := map[SourceName]bool{
		SourceNVD: true, SourceOSV: true, SourceGHSA: true,
		SourceAlpine: true, SourceDebian: true, SourceUbuntu: true,
		SourceRedHat: true, SourceALAS: true, SourceCISAKEV: true,
	}
	for _, s := range sources {
		if !expected[s] {
			t.Errorf("unexpected source in defaults: %s", s)
		}
	}
}

func TestAllSources_PrecedenceOrder(t *testing.T) {
	// Verify AllSources is in expected precedence order
	expectedOrder := []SourceName{
		SourceAlpine, SourceDebian, SourceUbuntu, SourceRedHat,
		SourceALAS, SourceGHSA, SourceOSV, SourceNVD, SourceCISAKEV,
	}

	if len(AllSources) != len(expectedOrder) {
		t.Fatalf("expected %d sources, got %d", len(expectedOrder), len(AllSources))
	}

	for i, s := range expectedOrder {
		if AllSources[i] != s {
			t.Errorf("position %d: expected %s, got %s", i, s, AllSources[i])
		}
	}
}
