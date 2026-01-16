package aws

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
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

	if conf.ScanEC2 {
		wg.Add(1)
		go func() { defer wg.Done(); scanEC2(cfg, p, conf) }()
	}
	if conf.ScanS3 {
		wg.Add(1)
		go func() { defer wg.Done(); scanS3(cfg, p, conf) }()
	}
	if conf.ScanRDS {
		wg.Add(1)
		go func() { defer wg.Done(); scanRDS(cfg, p, conf) }()
	}
	if conf.ScanElasti {
		wg.Add(1)
		go func() { defer wg.Done(); scanElasti(cfg, p, conf) }()
	}
	
	// FIXED BLOCK
	if conf.ScanECS {
		wg.Add(1)
		go func() { defer wg.Done(); scanECS(cfg, p, conf) }()
	}

	// FIXED BLOCK
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
