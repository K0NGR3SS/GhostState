package report

import (
	"bytes"
	"encoding/csv"
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCSVPropagatesBufferedWriteFailure(t *testing.T) {
	want := errors.New("disk full")
	if err := writeCSV(failedWriter{want}, sampleResults(), ExportMetadata{}); !errors.Is(err, want) {
		t.Fatalf("buffered write error was lost: %v", err)
	}
}

func TestCSVMetadataIsRectangularAndFormulaSafe(t *testing.T) {
	var dst bytes.Buffer
	results := map[string][]scanner.Resource{
		"=CATEGORY()": {{ID: " =HYPERLINK(\"evil\")", Tags: map[string]string{"z": "last", "a": "first"}, MonthlyCost: 1.25}},
	}
	err := writeCSV(&dst, results, ExportMetadata{
		ScanMode: "ALL", RegionMode: "CUSTOM", Regions: []string{"eu-west-1"},
		Errors: []scanner.ScanError{{Service: "S3", Region: "eu-west-1", Error: "=FORMULA()"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&dst).ReadAll()
	if err != nil {
		t.Fatalf("CSV cannot be read with a fixed schema: %v", err)
	}
	if rows[1][0] != "'=CATEGORY()" || !strings.HasPrefix(rows[1][5], "' =HYPERLINK") {
		t.Fatalf("formula not escaped: %v", rows[1])
	}
	if rows[1][8] != "1.25" || rows[1][16] != "a:first; z:last; " {
		t.Fatalf("numeric data or deterministic tags changed: %v", rows[1])
	}
	last := rows[len(rows)-1]
	if last[0] != "SCAN ERROR" || last[12] != "'=FORMULA()" {
		t.Fatalf("missing/unsafe scan error: %v", last)
	}
	if !strings.Contains(strings.Join(rows[len(rows)-2], " "), CostNote) {
		t.Fatal("missing cost caveat")
	}
}

func TestRepeatedExportsDoNotOverwriteAndUsePrivatePermissions(t *testing.T) {
	t.Chdir(t.TempDir())
	exporters := []func(map[string][]scanner.Resource) (string, error){GenerateCSV, ExportJSON, ExportHTML}
	for _, export := range exporters {
		first, err := export(sampleResults())
		if err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(first)
		if err != nil {
			t.Fatal(err)
		}
		second, err := export(nil)
		if err != nil {
			t.Fatal(err)
		}
		if first == second {
			t.Fatalf("reused filename %s", first)
		}
		after, err := os.ReadFile(first)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("earlier report was changed")
		}
		info, err := os.Stat(first)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("report permissions = %o", info.Mode().Perm())
		}
	}
}

func TestFailedExportRemovesIncompleteFile(t *testing.T) {
	t.Chdir(t.TempDir())
	results := sampleResults()
	results["COMPUTING"][0].MonthlyCost = math.NaN()
	filename, err := ExportJSON(results)
	if err == nil || filename != "" {
		t.Fatalf("filename=%q err=%v", filename, err)
	}
	files, err := os.ReadDir(".")
	if err != nil || len(files) != 0 {
		t.Fatalf("incomplete report left behind: %v, %v", files, err)
	}
}

func TestHTMLIncludesUnknownCategoriesAndEscapesResourceText(t *testing.T) {
	t.Chdir(t.TempDir())
	filename, err := ExportHTML(map[string][]scanner.Resource{"CUSTOM": {{ID: "<script>alert(1)</script>"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "CUSTOM") || !strings.Contains(string(raw), "&lt;script&gt;") || strings.Contains(string(raw), "<script>alert") {
		t.Fatal("HTML dropped a category or failed to escape resource text")
	}
}

func TestStreamingCloseAndManualExportPreserveData(t *testing.T) {
	t.Chdir(t.TempDir())
	stream, err := NewStreamingReportWriter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if err := stream.WriteResource("COMPUTING", scanner.Resource{ID: "streamed-resource"}); err != nil {
		t.Fatal(err)
	}
	filename, err := GenerateCSV(sampleResults())
	if err != nil {
		t.Fatal(err)
	}
	if filename == stream.GetFilename() {
		t.Fatal("manual export reused active streaming file")
	}
	if err := stream.WriteMetadata(ExportMetadata{}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
	if err := stream.WriteResource("", scanner.Resource{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
	raw, err := os.ReadFile(stream.GetFilename())
	if err != nil || !strings.Contains(string(raw), "streamed-resource") {
		t.Fatal("stream data lost")
	}
}
