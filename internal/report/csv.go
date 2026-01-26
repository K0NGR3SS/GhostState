package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

// StreamingReportWriter handles incremental CSV writing for large datasets
type StreamingReportWriter struct {
	writer   *csv.Writer
	file     *os.File
	filename string
}

// NewStreamingReportWriter creates a new streaming CSV writer
func NewStreamingReportWriter() (*StreamingReportWriter, error) {
	filename := fmt.Sprintf("ghoststate_report_%s.csv", time.Now().Format("2006-01-02_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}

	writer := csv.NewWriter(file)

	// Write CSV headers immediately
	headers := []string{
		"Category",
		"Service",
		"Type",
		"ID/Name",
		"Status",
		"Size",
		"MonthlyCost ($)",
		"IsGhost",
		"GhostInfo",
		"Risk",
		"RiskInfo",
		"Tags",
	}

	if err := writer.Write(headers); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write headers: %w", err)
	}

	writer.Flush()

	return &StreamingReportWriter{
		writer:   writer,
		file:     file,
		filename: filename,
	}, nil
}

// WriteResource writes a single resource to the CSV (called as resources are found)
func (w *StreamingReportWriter) WriteResource(category string, r scanner.Resource) error {
	tagsStr := ""
	for k, v := range r.Tags {
		tagsStr += fmt.Sprintf("%s:%s; ", k, v)
	}

	isGhost := "false"
	if r.IsGhost {
		isGhost = "true"
	}

	row := []string{
		category,
		r.Service,
		r.Type,
		r.ID,
		r.Status,
		fmt.Sprintf("%.2f", r.Size),
		fmt.Sprintf("%.2f", r.MonthlyCost),
		isGhost,
		r.GhostInfo,
		r.Risk,
		r.RiskInfo,
		tagsStr,
	}

	if err := w.writer.Write(row); err != nil {
		return fmt.Errorf("failed to write row: %w", err)
	}

	// Flush after each write to ensure data is saved incrementally
	w.writer.Flush()

	if err := w.writer.Error(); err != nil {
		return fmt.Errorf("csv writer error: %w", err)
	}

	return nil
}

// Close finalizes and closes the CSV file
func (w *StreamingReportWriter) Close() error {
	w.writer.Flush()
	if err := w.writer.Error(); err != nil {
		w.file.Close()
		return fmt.Errorf("error flushing writer: %w", err)
	}
	return w.file.Close()
}

// GetFilename returns the generated filename
func (w *StreamingReportWriter) GetFilename() string {
	return w.filename
}

// GenerateCSV - Original function (kept for backward compatibility)
func GenerateCSV(results map[string][]scanner.Resource) (string, error) {
	filename := fmt.Sprintf("ghoststate_report_%s.csv", time.Now().Format("2006-01-02_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{
		"Category",
		"Service",
		"Type",
		"ID/Name",
		"Status",
		"Size",
		"MonthlyCost ($)",
		"IsGhost",
		"GhostInfo",
		"Risk",
		"RiskInfo",
		"Tags",
	}

	if err := writer.Write(headers); err != nil {
		return "", err
	}

	for category, resources := range results {
		for _, r := range resources {
			tagsStr := ""
			for k, v := range r.Tags {
				tagsStr += fmt.Sprintf("%s:%s; ", k, v)
			}

			isGhost := "false"
			if r.IsGhost {
				isGhost = "true"
			}

			row := []string{
				category,
				r.Service,
				r.Type,
				r.ID,
				r.Status,
				fmt.Sprintf("%.2f", r.Size),
				fmt.Sprintf("%.2f", r.MonthlyCost),
				isGhost,
				r.GhostInfo,
				r.Risk,
				r.RiskInfo,
				tagsStr,
			}

			if err := writer.Write(row); err != nil {
				return "", err
			}
		}
	}

	return filename, nil
}