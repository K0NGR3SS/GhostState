package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

var csvHeaders = []string{
	"Category", "AccountID", "Region", "Service", "Type", "ID/Name",
	"Status", "Size", "MonthlyCost ($)", "IsGhost", "GhostInfo", "Risk",
	"RiskInfo", "Recommendation", "SavingsEstimate ($)", "ControlRefs", "Tags", "Notes",
}

// csvText prevents untrusted resource names, tags, and errors from being
// interpreted as spreadsheet formulas when a report is opened in Excel/Calc.
func csvText(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.ContainsAny(value, "\t\r\n") || (trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
		return "'" + value
	}
	return value
}

func resourceRow(category string, r scanner.Resource) []string {
	keys := make([]string, 0, len(r.Tags))
	for key := range r.Tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var tags strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&tags, "%s:%s; ", key, r.Tags[key])
	}
	row := []string{
		category, r.AccountID, r.Region, r.Service, r.Type, r.ID, r.Status,
		fmt.Sprintf("%.2f", r.Size), fmt.Sprintf("%.2f", r.MonthlyCost), strconv.FormatBool(r.IsGhost),
		r.GhostInfo, r.Risk, r.RiskInfo, r.Recommendation,
		fmt.Sprintf("%.2f", r.SavingsEstimate), strings.Join(r.ControlRefs, "; "), tags.String(), r.Info,
	}
	for i := range row {
		if i != 7 && i != 8 && i != 9 && i != 14 {
			row[i] = csvText(row[i])
		}
	}
	return row
}

func writeMetadata(writer *csv.Writer, meta ExportMetadata) error {
	if meta.CostNote == "" {
		meta.CostNote = CostNote
	}
	for _, field := range [][2]string{
		{"ScanMode", meta.ScanMode}, {"RegionMode", meta.RegionMode},
		{"Regions", strings.Join(meta.Regions, ", ")}, {"CostNote", meta.CostNote},
	} {
		if field[1] == "" {
			continue
		}
		row := make([]string, len(csvHeaders))
		row[0], row[4], row[5] = "SCAN METADATA", field[0], csvText(field[1])
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	for _, scanErr := range meta.Errors {
		row := make([]string, len(csvHeaders))
		row[0], row[2], row[3] = "SCAN ERROR", csvText(scanErr.Region), csvText(scanErr.Service)
		row[11], row[12] = "ERROR", csvText(scanErr.Error)
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

// StreamingReportWriter is owned by the UI event loop, not concurrent scan workers.
type StreamingReportWriter struct {
	writer   *csv.Writer
	file     *os.File
	closed   bool
	closeErr error
}

func NewStreamingReportWriter() (*StreamingReportWriter, error) {
	file, err := newReportFile("csv")
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}
	writer := csv.NewWriter(file)
	err = writer.Write(csvHeaders)
	writer.Flush()
	if err == nil {
		err = writer.Error()
	}
	if err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, fmt.Errorf("failed to write headers: %w", err)
	}
	return &StreamingReportWriter{writer: writer, file: file}, nil
}

func (w *StreamingReportWriter) WriteResource(category string, r scanner.Resource) error {
	if w.closed {
		return os.ErrClosed
	}
	if err := w.writer.Write(resourceRow(category, r)); err != nil {
		return err
	}
	w.writer.Flush()
	return w.writer.Error()
}

func (w *StreamingReportWriter) WriteMetadata(meta ExportMetadata) error {
	if w.closed {
		return os.ErrClosed
	}
	return writeMetadata(w.writer, meta)
}

// Close is idempotent, allowing both normal completion and shutdown cleanup.
func (w *StreamingReportWriter) Close() error {
	if w.closed {
		return w.closeErr
	}
	w.closed = true
	w.writer.Flush()
	w.closeErr = w.writer.Error()
	if err := w.file.Close(); w.closeErr == nil {
		w.closeErr = err
	}
	return w.closeErr
}

func (w *StreamingReportWriter) GetFilename() string { return w.file.Name() }

func GenerateCSV(results map[string][]scanner.Resource) (string, error) {
	return GenerateCSVWithMetadata(results, ExportMetadata{})
}

func GenerateCSVWithMetadata(results map[string][]scanner.Resource, meta ExportMetadata) (filename string, err error) {
	file, err := newReportFile("csv")
	if err != nil {
		return "", err
	}
	defer finishReport(file, &filename, &err)
	if err := writeCSV(file, results, meta); err != nil {
		return "", err
	}
	return file.Name(), nil
}

func writeCSV(dst io.Writer, results map[string][]scanner.Resource, meta ExportMetadata) error {
	writer := csv.NewWriter(dst)
	if err := writer.Write(csvHeaders); err != nil {
		return err
	}
	categories := make([]string, 0, len(results))
	for category := range results {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	for _, category := range categories {
		for _, r := range results[category] {
			if err := writer.Write(resourceRow(category, r)); err != nil {
				return err
			}
		}
	}
	return writeMetadata(writer, meta)
}
