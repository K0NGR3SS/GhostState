package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

func withTempWorkingDir(t *testing.T) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working dir: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("change working dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore working dir: %v", err)
		}
	})
}

func sampleResults() map[string][]scanner.Resource {
	return map[string][]scanner.Resource{
		"COMPUTING": {
			{
				AccountID:       "123456789012",
				Region:          "eu-west-1",
				Service:         "EC2",
				Type:            "t3.micro",
				ID:              "i-123",
				Risk:            "HIGH",
				RiskInfo:        "Public IP",
				Recommendation:  "Remove public exposure",
				ControlRefs:     []string{"SecurityHub EC2.9"},
				MonthlyCost:     9.50,
				SavingsEstimate: 3.65,
			},
		},
	}
}

func TestExportJSONWithMetadataIncludesScanErrorsAndSavings(t *testing.T) {
	withTempWorkingDir(t)

	filename, err := ExportJSONWithMetadata(sampleResults(), ExportMetadata{
		ScanMode:     "ALL",
		RegionMode:   "CUSTOM REGIONS",
		Regions:      []string{"eu-west-1"},
		TotalSavings: 3.65,
		Errors:       []scanner.ScanError{{Service: "S3", Region: "global", Error: "denied"}},
	})
	if err != nil {
		t.Fatalf("export json: %v", err)
	}

	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read json: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if payload["total_savings"].(float64) != 3.65 {
		t.Fatalf("total_savings = %v", payload["total_savings"])
	}
	scan := payload["scan"].(map[string]any)
	if scan["scan_mode"] != "ALL" {
		t.Fatalf("scan metadata = %#v", scan)
	}
}

func TestGenerateCSVWithMetadataIncludesActionColumns(t *testing.T) {
	withTempWorkingDir(t)

	filename, err := GenerateCSVWithMetadata(sampleResults(), ExportMetadata{})
	if err != nil {
		t.Fatalf("export csv: %v", err)
	}

	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	content := string(raw)
	for _, want := range []string{"Recommendation", "SavingsEstimate ($)", "ControlRefs", "Remove public exposure"} {
		if !strings.Contains(content, want) {
			t.Fatalf("csv missing %q:\n%s", want, content)
		}
	}
}
