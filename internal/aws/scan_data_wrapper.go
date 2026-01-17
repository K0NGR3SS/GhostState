package aws

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/K0NGR3SS/GhostState/internal/scanner/data"
)

func scanS3(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := data.NewS3Scanner(cfg)
	runScan(p, s, conf)
}

func scanRDS(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := data.NewRDSScanner(cfg)
	runScan(p, s, conf)
}

func scanElasti(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	s := data.NewElastiScanner(cfg)
	runScan(p, s, conf)
}

func scanDynamoDB(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	rule := scanner.AuditRule{TargetKey: conf.TargetKey, TargetVal: conf.TargetVal}
	
	// 1. Get Account ID needed for ARN construction
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		send(p, "DynamoDB Error: Failed to get Account ID")
		return
	}

	// 2. Pass Config, AccountID, and Region to Constructor
	s := data.NewDynamoDBScanner(cfg, *identity.Account, cfg.Region)
	
	// 3. Call Scan with just context and rule
	res, err := s.Scan(context.TODO(), rule)
	if err != nil {
		send(p, "DynamoDB Error: "+err.Error())
		return
	}
	
	for _, r := range res {
		send(p, fmt.Sprintf("%s: %s", r.Type, r.ID))
	}
}
