package aws

import (

	"github.com/aws/aws-sdk-go-v2/aws"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/K0NGR3SS/GhostState/internal/scanner/computing"
)

func scanEC2(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := computing.NewEC2Scanner(cfg)
	runScan(p, s, conf)
}

func scanECS(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := computing.NewECSScanner(cfg)
	runScan(p, s, conf)
}

func scanLambda(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := computing.NewLambdaScanner(cfg)
	runScan(p, s, conf)
}
