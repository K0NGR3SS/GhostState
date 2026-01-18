package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/computing"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/data"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/monitoring"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/network"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/security"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type Provider struct {
	cfg       aws.Config
	accountID string
	region    string
}

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

func (p *Provider) ScanAll(ctx context.Context, conf scanner.AuditConfig) ([]scanner.Resource, error) {
	var results []scanner.Resource
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Helper closure to run scans safely
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
	if conf.ScanEKS {
		wg.Add(1)
		go run(computing.NewEKSScanner(p.cfg))
	}
	if conf.ScanECR {
		wg.Add(1)
		go run(computing.NewECRScanner(p.cfg))
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
	// [FIXED] Using the correct helper `run` and `p.cfg`
	if conf.ScanDynamoDB {
		wg.Add(1)
		go run(data.NewDynamoDBScanner(p.cfg))
	}
	if conf.ScanElasti {
		wg.Add(1)
		go run(data.NewElastiScanner(p.cfg))
	}
	if conf.ScanEBS {
		wg.Add(1)
		go run(data.NewEBSScanner(p.cfg))
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
	if conf.ScanEIP {
		wg.Add(1)
		go run(network.NewEIPScanner(p.cfg))
	}
	if conf.ScanELB {
		wg.Add(1)
		go run(network.NewELBScanner(p.cfg))
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
	if conf.ScanIAM {
		wg.Add(1)
		go run(security.NewIAMScanner(p.cfg))
	}
	if conf.ScanSecrets {
		wg.Add(1)
		go run(security.NewSecretsScanner(p.cfg))
	}
	if conf.ScanKMS {
		wg.Add(1)
		go run(security.NewKMSScanner(p.cfg))
	}

	// --- Monitoring ---
	if conf.ScanCloudWatch {
		wg.Add(1)
		go run(monitoring.NewCloudWatchScanner(p.cfg))
	}

	wg.Wait()
	return results, nil
}
