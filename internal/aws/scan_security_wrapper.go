package aws

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/K0NGR3SS/GhostState/internal/scanner/security"
)

func scanACM(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := security.NewACMScanner(cfg)
	rule := scanner.AuditRule{TargetKey: conf.TargetKey, TargetVal: conf.TargetVal}

	res, err := s.Scan(context.TODO(), rule)
	if err != nil {
		send(p, "ACM Error: "+err.Error())
		return
	}
	for _, r := range res {
		send(p, fmt.Sprintf("%s: %s", r.Type, r.ID))
	}
}

func scanSecGroups(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := security.NewSGScanner(cfg)
	rule := scanner.AuditRule{TargetKey: conf.TargetKey, TargetVal: conf.TargetVal}

	res, err := s.Scan(context.TODO(), rule)
	if err != nil {
		send(p, "SG Error: "+err.Error())
		return
	}
	for _, r := range res {
		send(p, fmt.Sprintf("%s: %s", r.Type, r.ID))
	}
}

