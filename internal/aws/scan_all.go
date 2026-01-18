package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

func ScanAll(p *tea.Program, conf scanner.AuditConfig) {
	// 1. Load AWS Config
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		p.Send(FoundMsg(fmt.Sprintf("Error loading AWS config: %v", err)))
		p.Send(FinishedMsg{})
		return
	}

	provider, err := NewProvider(cfg)
	if err != nil {
		p.Send(FoundMsg(fmt.Sprintf("Error initializing provider: %v", err)))
		p.Send(FinishedMsg{})
		return
	}
	results, err := provider.ScanAll(context.TODO(), conf)
	if err != nil {
		p.Send(FoundMsg(fmt.Sprintf("Scan error: %v", err)))
	}
	for _, res := range results {
		msg := fmt.Sprintf("[%s] %s", res.Type, res.ID)
		p.Send(FoundMsg(msg))
	}
	p.Send(FinishedMsg{})
}
