package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

func GenerateCSV(results map[string][]scanner.Resource) (string, error) {
	filename := fmt.Sprintf("ghoststate_report_%s.csv", time.Now().Format("2006-01-02_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Category", "Type", "ID/Name", "IsGhost", "GhostInfo", "Risk", "RiskInfo", "Tags"}
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
				r.Type,
				r.ID,
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
