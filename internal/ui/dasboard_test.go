package ui

import (
	"testing"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

func TestParseRegionListDedupesAndTrims(t *testing.T) {
	got := parseRegionList(" us-east-1, eu-west-1,us-east-1,, ap-southeast-2 ")
	want := []string{"us-east-1", "eu-west-1", "ap-southeast-2"}

	if len(got) != len(want) {
		t.Fatalf("got %d regions, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("region %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFilterResultsQuickFiltersAndSearch(t *testing.T) {
	m := InitialModel()
	items := []scanner.Resource{
		{ID: "sg-open", Service: "Security Group", Risk: "HIGH", RiskInfo: "Open to World"},
		{ID: "vol-unused", Service: "EBS", IsGhost: true, SavingsEstimate: 7.5},
		{ID: "bucket-safe", Service: "S3", Risk: "SAFE", Recommendation: "Enable versioning"},
	}

	m.quickFilter = "SAVINGS"
	got := m.filterResults(items)
	if len(got) != 1 || got[0].ID != "vol-unused" {
		t.Fatalf("savings filter returned %#v", got)
	}

	m.quickFilter = ""
	m.searchFilter = "versioning"
	got = m.filterResults(items)
	if len(got) != 1 || got[0].ID != "bucket-safe" {
		t.Fatalf("recommendation search returned %#v", got)
	}
}
