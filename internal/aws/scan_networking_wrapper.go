package aws

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/K0NGR3SS/GhostState/internal/scanner/networking"
)

func scanVPC(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := networking.NewVPCScanner(cfg)
	runScan(p, s, conf)
}

func scanCloudfront(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := networking.NewCloudFrontScanner(cfg)
	runScan(p, s, conf)
}
