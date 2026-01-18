package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/computing"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/data"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/network"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/security"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

// Provider holds the AWS configuration
type Provider struct {
	cfg       aws.Config
	accountID string
	region    string
}

// NewProvider creates a new AWS provider
func NewProvider(cfg aws.Config) (*Provider, error) {
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS identity: %w", err)
	}

	return &Provider{
		cfg:       cfg,
		accountID: *identity.Account,
		region:    cfg.Region,
	}, nil
}

// ScanAll orchestrates the scanning of all requested services
func (p *Provider) ScanAll(ctx context.Context, conf scanner.AuditConfig) ([]scanner.Resource, error) {
	var results []scanner.Resource
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Helper to run a scanner concurrently
	run := func(s interface {
		Scan(context.Context, scanner.AuditRule) ([]scanner.Resource, error)
	}) {
		defer wg.Done()
		res, err := s.Scan(ctx, conf.TargetRule)
		if err == nil {
			mu.Lock()
			results = append(results, res...)
			mu.Unlock()
		}
	}

	// --- Computing ---
	if conf.ScanEC2 {
		wg.Add(1)
		go run(computing.NewEC2Scanner(p.cfg))
	}
	if conf.ScanECS {
		wg.Add(1)
		go run(computing.NewECSScanner(p.cfg))
	}
	if conf.ScanLambda {
		wg.Add(1)
		go run(computing.NewLambdaScanner(p.cfg))
	}

	// --- Data ---
	if conf.ScanS3 {
		wg.Add(1)
		go run(data.NewS3Scanner(p.cfg))
	}
	if conf.ScanRDS {
		wg.Add(1)
		go run(data.NewRDSScanner(p.cfg))
	}
	if conf.ScanDynamoDB {
		wg.Add(1)
		go run(data.NewDynamoDBScanner(p.cfg, p.accountID, p.region))
	}
	if conf.ScanElasti {
		wg.Add(1)
		go run(data.NewElastiScanner(p.cfg))
	}

	// --- Network ---
	if conf.ScanVPC {
		wg.Add(1)
		go run(network.NewVPCScanner(p.cfg))
	}
	if conf.ScanCloudfront {
		wg.Add(1)
		go run(network.NewCloudFrontScanner(p.cfg))
	}

	// --- Security ---
	if conf.ScanACM {
		wg.Add(1)
		go run(security.NewACMScanner(p.cfg))
	}
	if conf.ScanSecGroups {
		wg.Add(1)
		go run(security.NewSGScanner(p.cfg))
	}

	wg.Wait()
	return results, nil
}
