package aws

import (
	"context"
	"fmt"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	tea "github.com/charmbracelet/bubbletea"
)

// FoundMsg carries the full resource object
type FoundMsg scanner.Resource

// ScanErrorMsg reports a scanner failure without aborting the whole scan.
type ScanErrorMsg scanner.ScanError

// StatusMsg reports scan setup/progress text to the UI.
type StatusMsg string

// FinishedMsg signals completion
type FinishedMsg struct{}

func ScanAll(p *tea.Program, conf scanner.AuditConfig) {
	p.Send(StatusMsg("Loading AWS configuration..."))

	// Load config with retry logic
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRetryer(func() aws.Retryer {
			return retry.AddWithMaxAttempts(retry.NewStandard(), 5)
		}),
	)
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

	p.Send(StatusMsg("Identifying AWS account..."))
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

	p.Send(StatusMsg("Scanning selected services..."))
	results, scanErrors, err := provider.ScanAll(context.TODO(), conf)
	if err != nil {
		p.Send(FoundMsg(scanner.Resource{
			ID:   fmt.Sprintf("Scan Error: %v", err),
			Type: "❌ SCAN ERROR",
			Risk: "HIGH",
		}))
	}

	for _, scanErr := range scanErrors {
		p.Send(ScanErrorMsg(scanErr))
	}

	for _, res := range results {
		p.Send(FoundMsg(res))
	}
	p.Send(FinishedMsg{})
}
