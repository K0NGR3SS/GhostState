package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

// FoundMsg carries the full resource object
type FoundMsg scanner.Resource 

// FinishedMsg signals completion
type FinishedMsg struct{}

func ScanAll(p *tea.Program, conf scanner.AuditConfig) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
        // Create an "Error Resource" to display the failure
		p.Send(FoundMsg(scanner.Resource{
			ID:   fmt.Sprintf("Error loading AWS config: %v", err),
			Type: "❌ FATAL ERROR",
            Risk: "CRITICAL",
		}))
		p.Send(FinishedMsg{})
		return
	}

	provider, err := NewProvider(cfg)
	if err != nil {
		p.Send(FoundMsg(scanner.Resource{
			ID:   fmt.Sprintf("Error initializing provider: %v", err),
			Type: "❌ FATAL ERROR",
            Risk: "CRITICAL",
		}))
		p.Send(FinishedMsg{})
		return
	}

	results, err := provider.ScanAll(context.TODO(), conf)
	if err != nil {
        p.Send(FoundMsg(scanner.Resource{
			ID:   fmt.Sprintf("Scan Error: %v", err),
			Type: "❌ SCAN ERROR",
            Risk: "HIGH",
		}))
	}
	
	for _, res := range results {
		p.Send(FoundMsg(res))
	}
	p.Send(FinishedMsg{})
}
