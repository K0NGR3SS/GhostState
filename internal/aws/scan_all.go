package aws

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	tea "github.com/charmbracelet/bubbletea"
)

// FoundMsg carries the full resource object.
type FoundMsg scanner.Resource

// ScanErrorMsg reports a scanner failure without aborting the whole scan.
type ScanErrorMsg scanner.ScanError

type StatusMsg string

// RegionsMsg reports the resolved scope, including current/all-region selections.
type RegionsMsg []string

type FinishedMsg struct{}

// ScanAll sends results as services finish. The caller owns cancellation and must
// provide a concurrency-safe send function that unblocks when ctx is canceled.
func ScanAll(ctx context.Context, send func(tea.Msg), conf scanner.AuditConfig) {
	defer send(FinishedMsg{})
	send(StatusMsg("Loading AWS configuration..."))
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRetryer(func() aws.Retryer {
			return retry.AddWithMaxAttempts(retry.NewStandard(), 5)
		}),
	)
	if err != nil {
		send(ScanErrorMsg{Service: "AWS configuration", Error: err.Error()})
		return
	}

	send(StatusMsg("Identifying AWS account..."))
	provider, err := NewProvider(ctx, cfg)
	if err != nil {
		send(ScanErrorMsg{Service: "AWS identity", Region: cfg.Region, Error: err.Error()})
		return
	}

	send(StatusMsg("Scanning selected services..."))
	_, _, err = provider.ScanAllWithProgress(ctx, conf, ScanProgress{
		Resource: func(r scanner.Resource) { send(FoundMsg(r)) },
		Error:    func(e scanner.ScanError) { send(ScanErrorMsg(e)) },
		Regions:  func(regions []string) { send(RegionsMsg(regions)) },
	})
	if err != nil {
		send(ScanErrorMsg{Service: "Scan", Error: err.Error()})
	}
}
