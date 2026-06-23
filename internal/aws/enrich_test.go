package aws

import (
	"strings"
	"testing"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

func TestEnrichResourceAddsSecurityGroupRecommendation(t *testing.T) {
	got := EnrichResource(scanner.Resource{
		Service:  "Security Group",
		Risk:     "CRITICAL",
		RiskInfo: "Open to World: SSH (22)",
	})

	if got.Recommendation == "" {
		t.Fatal("expected recommendation")
	}
	if len(got.ControlRefs) == 0 {
		t.Fatal("expected control references")
	}
	if !strings.Contains(strings.ToLower(got.Recommendation), "restrict") {
		t.Fatalf("unexpected recommendation: %q", got.Recommendation)
	}
}

func TestEnrichResourceEstimatesGhostSavings(t *testing.T) {
	got := EnrichResource(scanner.Resource{
		Service:     "EBS Volume",
		Type:        "gp3",
		IsGhost:     true,
		MonthlyCost: 12.25,
	})

	if got.SavingsEstimate != 12.25 {
		t.Fatalf("SavingsEstimate = %.2f, want 12.25", got.SavingsEstimate)
	}
}

func TestEstimateCostUsesGP2Baseline(t *testing.T) {
	got := EstimateCost("EBS Volume", "gp2", 100)
	if got != 10.0 {
		t.Fatalf("EstimateCost gp2 = %.2f, want 10.00", got)
	}
}
