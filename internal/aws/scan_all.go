package aws

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/K0NGR3SS/GhostState/internal/scanner/computing"
	"github.com/K0NGR3SS/GhostState/internal/scanner/data"
	"github.com/K0NGR3SS/GhostState/internal/scanner/networking"
	"github.com/K0NGR3SS/GhostState/internal/scanner/security"
	tea "github.com/charmbracelet/bubbletea"
)

func ScanAll(p *tea.Program, conf AuditConfig) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		send(p, "Error loading AWS config: "+err.Error())
		if p != nil {
			p.Send(FinishedMsg{})
		}
		return
	}

	var wg sync.WaitGroup

	// Computing
	if conf.ScanEC2 {
		wg.Add(1)
		go func() { defer wg.Done(); scanEC2(cfg, p, conf) }()
	}
	if conf.ScanECS {
		wg.Add(1)
		go func() { defer wg.Done(); scanECS(cfg, p, conf) }()
	}
	if conf.ScanLambda {
		wg.Add(1)
		go func() { defer wg.Done(); scanLambda(cfg, p, conf) }()
	}

	// Data
	if conf.ScanS3 {
		wg.Add(1)
		go func() { defer wg.Done(); scanS3(cfg, p, conf) }()
	}
	if conf.ScanRDS {
		wg.Add(1)
		go func() { defer wg.Done(); scanRDS(cfg, p, conf) }()
	}
	if conf.ScanDynamoDB {
		wg.Add(1)
		go func() { defer wg.Done(); scanDynamoDB(cfg, p, conf) }()
	}
	if conf.ScanElasti {
		wg.Add(1)
		go func() { defer wg.Done(); scanElasti(cfg, p, conf) }()
	}

	// Networking & Security
	if conf.ScanVPC {
		wg.Add(1)
		go func() { defer wg.Done(); scanVPC(cfg, p, conf) }()
	}
	if conf.ScanCloudfront {
		wg.Add(1)
		go func() { defer wg.Done(); scanCloudfront(cfg, p, conf) }()
	}
	if conf.ScanACM {
		wg.Add(1)
		go func() { defer wg.Done(); scanACM(cfg, p, conf) }()
	}
	if conf.ScanSecGroups {
		wg.Add(1)
		go func() { defer wg.Done(); scanSecGroups(cfg, p, conf) }()
	}

	wg.Wait()
	if p != nil {
		p.Send(FinishedMsg{})
	}
}
