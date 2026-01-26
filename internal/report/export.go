package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type CategoryData struct {
	Name      string
	Resources []ResourceData
}

type ResourceData struct {
	ID          string
	Type        string
	Region      string
	Risk        string
	RiskClass   string
	IsGhost     bool
	RiskInfo    string
	GhostInfo   string
	MonthlyCost float64
}

func ExportJSON(results map[string][]scanner.Resource) (string, error) {
	filename := fmt.Sprintf("ghoststate_report_%s.json", time.Now().Format("2006-01-02_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	export := map[string]interface{}{
		"generated_at": time.Now().Format(time.RFC3339),
		"total_resources": func() int {
			count := 0
			for _, resources := range results {
				count += len(resources)
			}
			return count
		}(),
		"total_cost": func() float64 {
			cost := 0.0
			for _, resources := range results {
				for _, r := range resources {
					cost += r.MonthlyCost
				}
			}
			return cost
		}(),
		"categories": results,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(export); err != nil {
		return "", fmt.Errorf("failed to encode JSON: %w", err)
	}

	return filename, nil
}

func ExportHTML(results map[string][]scanner.Resource) (string, error) {
	filename := fmt.Sprintf("ghoststate_report_%s.html", time.Now().Format("2006-01-02_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	totalResources := 0
	totalCost := 0.0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	ghostCount := 0

	for _, resources := range results {
		totalResources += len(resources)
		for _, r := range resources {
			totalCost += r.MonthlyCost
			switch r.Risk {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			}
			if r.IsGhost {
				ghostCount++
			}
		}
	}

	categoryOrder := []string{"COMPUTING", "DATA & STORAGE", "NETWORKING", "SECURITY & IDENTITY", "MONITORING", "OTHER"}

	var categories []CategoryData
	for _, catName := range categoryOrder {
		if resources, ok := results[catName]; ok && len(resources) > 0 {
			var resourceList []ResourceData
			for _, r := range resources {
				riskClass := strings.ToLower(r.Risk)
				resourceList = append(resourceList, ResourceData{
					ID:          r.ID,
					Type:        r.Type,
					Region:      r.Region,
					Risk:        r.Risk,
					RiskClass:   riskClass,
					IsGhost:     r.IsGhost,
					RiskInfo:    r.RiskInfo,
					GhostInfo:   r.GhostInfo,
					MonthlyCost: r.MonthlyCost,
				})
			}
			categories = append(categories, CategoryData{
				Name:      catName,
				Resources: resourceList,
			})
		}
	}

	data := map[string]interface{}{
		"Timestamp":      time.Now().Format("January 2, 2006 at 3:04 PM"),
		"TotalResources": totalResources,
		"CriticalCount":  criticalCount,
		"HighCount":      highCount,
		"MediumCount":    mediumCount,
		"GhostCount":     ghostCount,
		"TotalCost":      totalCost,
		"Categories":     categories,
	}

	tmpl := template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>GhostState Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1b26 0%, #24283b 100%);
            color: #c0caf5;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #1a1b26;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #f2c85b 0%, #e0ac00 100%);
            color: #1a1b26;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #24283b;
        }
        .stat-card {
            background: #1a1b26;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 2px solid #414868;
        }
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-card .label {
            font-size: 0.9em;
            color: #565f89;
            text-transform: uppercase;
        }
        .stat-card.critical .number { color: #f7768e; }
        .stat-card.high .number { color: #ff9e64; }
        .stat-card.medium .number { color: #e0af68; }
        .stat-card.ghost .number { color: #7aa2f7; }
        .stat-card.cost .number { color: #9ece6a; }
        .category {
            padding: 30px;
            border-bottom: 1px solid #414868;
        }
        .category:last-child { border-bottom: none; }
        .category h2 {
            color: #7aa2f7;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        .resource-table {
            width: 100%;
            border-collapse: collapse;
            background: #24283b;
            border-radius: 8px;
            overflow: hidden;
        }
        .resource-table th {
            background: #414868;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #c0caf5;
        }
        .resource-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #414868;
        }
        .resource-table tr:last-child td {
            border-bottom: none;
        }
        .resource-table tr:hover {
            background: #1a1b26;
        }
        .risk-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .risk-critical {
            background: #f7768e;
            color: #1a1b26;
        }
        .risk-high {
            background: #ff9e64;
            color: #1a1b26;
        }
        .risk-medium {
            background: #e0af68;
            color: #1a1b26;
        }
        .risk-low {
            background: #7aa2f7;
            color: #1a1b26;
        }
        .risk-safe {
            background: #9ece6a;
            color: #1a1b26;
        }
        .ghost-badge {
            background: #565f89;
            color: #c0caf5;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-left: 8px;
        }
        .cost {
            color: #9ece6a;
            font-weight: 600;
        }
        .footer {
            padding: 20px;
            text-align: center;
            color: #565f89;
            font-size: 0.9em;
            background: #24283b;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ GhostState Security Report</h1>
            <div class="subtitle">Generated on {{.Timestamp}}</div>
        </div>

        <div class="summary">
            <div class="stat-card">
                <div class="number">{{.TotalResources}}</div>
                <div class="label">Total Resources</div>
            </div>
            <div class="stat-card critical">
                <div class="number">{{.CriticalCount}}</div>
                <div class="label">Critical Issues</div>
            </div>
            <div class="stat-card high">
                <div class="number">{{.HighCount}}</div>
                <div class="label">High Risk</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{{.MediumCount}}</div>
                <div class="label">Medium Risk</div>
            </div>
            <div class="stat-card ghost">
                <div class="number">{{.GhostCount}}</div>
                <div class="label">Ghost Resources</div>
            </div>
            <div class="stat-card cost">
                <div class="number">${{printf "%.2f" .TotalCost}}</div>
                <div class="label">Monthly Cost</div>
            </div>
        </div>

        {{range .Categories}}
        <div class="category">
            <h2>{{.Name}}</h2>
            <table class="resource-table">
                <thead>
                    <tr>
                        <th>Resource ID</th>
                        <th>Type</th>
                        <th>Region</th>
                        <th>Risk Level</th>
                        <th>Details</th>
                        <th>Monthly Cost</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Resources}}
                    <tr>
                        <td>{{.ID}}</td>
                        <td>{{.Type}}</td>
                        <td>{{.Region}}</td>
                        <td>
                            <span class="risk-badge risk-{{.RiskClass}}">{{.Risk}}</span>
                            {{if .IsGhost}}<span class="ghost-badge">👻 GHOST</span>{{end}}
                        </td>
                        <td>
                            {{if .RiskInfo}}{{.RiskInfo}}{{end}}
                            {{if .GhostInfo}}{{if .RiskInfo}}<br>{{end}}Ghost: {{.GhostInfo}}{{end}}
                        </td>
                        <td class="cost">${{printf "%.2f" .MonthlyCost}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        <div class="footer">
            <p>Generated by GhostState - AWS Security & Cost Analysis Tool</p>
            <p>🛡️ Protecting your cloud infrastructure</p>
        </div>
    </div>
</body>
</html>`))

	if err := tmpl.Execute(file, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return filename, nil
}
