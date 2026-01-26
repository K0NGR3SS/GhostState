package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
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

// Get all enabled AWS regions
func (p *Provider) GetAllRegions(ctx context.Context) ([]string, error) {
	ec2Client := ec2.NewFromConfig(p.cfg)
	result, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false), // Only enabled regions
	})
	if err != nil {
		return nil, err
	}

	var regions []string
	for _, region := range result.Regions {
		if region.RegionName != nil {
			regions = append(regions, *region.RegionName)
		}
	}
	return regions, nil
}

func (p *Provider) scanRegion(ctx context.Context, region string, conf scanner.AuditConfig) []scanner.Resource {
	// Create region-specific config
	regionalCfg := p.cfg.Copy()
	regionalCfg.Region = region

	resultsChan := make(chan scanner.Resource, 1000)
	var wg sync.WaitGroup

	run := func(s interface {
		Scan(context.Context, scanner.AuditRule) ([]scanner.Resource, error)
	}) {
		defer wg.Done()
		res, err := s.Scan(ctx, conf.TargetRule)
		if err == nil {
			for _, r := range res {
				r.Region = region // Tag resource with region
				resultsChan <- r
			}
		}
	}

	// --- Computing ---
	if conf.ScanEC2 {
		wg.Add(1)
		go run(computing.NewEC2Scanner(regionalCfg))
	}
	if conf.ScanECS {
		wg.Add(1)
		go run(computing.NewECSScanner(regionalCfg))
	}
	if conf.ScanLambda {
		wg.Add(1)
		go run(computing.NewLambdaScanner(regionalCfg))
	}
	if conf.ScanEKS {
		wg.Add(1)
		go run(computing.NewEKSScanner(regionalCfg))
	}
	if conf.ScanECR {
		wg.Add(1)
		go run(computing.NewECRScanner(regionalCfg))
	}

	// --- Data ---
	if conf.ScanS3 && region == "us-east-1" {
		// S3 is global, only scan once
		wg.Add(1)
		go run(data.NewS3Scanner(regionalCfg))
	}
	if conf.ScanRDS {
		wg.Add(1)
		go run(data.NewRDSScanner(regionalCfg))
	}
	if conf.ScanDynamoDB {
		wg.Add(1)
		go run(data.NewDynamoDBScanner(regionalCfg))
	}
	if conf.ScanElasti {
		wg.Add(1)
		go run(data.NewElastiScanner(regionalCfg))
	}
	if conf.ScanEBS {
		wg.Add(1)
		go run(data.NewEBSScanner(regionalCfg))
	}

	// --- Network ---
	if conf.ScanVPC {
		wg.Add(1)
		go run(network.NewVPCScanner(regionalCfg))
	}
	if conf.ScanCloudfront && region == "us-east-1" {
		// CloudFront is global, only scan once
		wg.Add(1)
		go run(network.NewCloudFrontScanner(regionalCfg))
	}
	if conf.ScanEIP {
		wg.Add(1)
		go run(network.NewEIPScanner(regionalCfg))
	}
	if conf.ScanELB {
		wg.Add(1)
		go run(network.NewELBScanner(regionalCfg))
	}
	if conf.ScanRoute53 && region == "us-east-1" {
		// Route53 is global
		wg.Add(1)
		go run(network.NewRoute53Scanner(regionalCfg))
	}

	// --- Security ---
	if conf.ScanACM {
		wg.Add(1)
		go run(security.NewACMScanner(regionalCfg))
	}
	if conf.ScanSecGroups {
		wg.Add(1)
		go run(security.NewSGScanner(regionalCfg))
	}
	if conf.ScanIAM && region == "us-east-1" {
		// IAM is global
		wg.Add(1)
		go run(security.NewIAMScanner(regionalCfg))
	}
	if conf.ScanSecrets {
		wg.Add(1)
		go run(security.NewSecretsScanner(regionalCfg))
	}
	if conf.ScanKMS {
		wg.Add(1)
		go run(security.NewKMSScanner(regionalCfg))
	}
	if conf.ScanCloudTrail {
		wg.Add(1)
		go run(security.NewTrailScanner(regionalCfg))
	}

	// --- Monitoring ---
	if conf.ScanCloudWatch {
		wg.Add(1)
		go run(monitoring.NewCloudWatchScanner(regionalCfg))
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []scanner.Resource
	for res := range resultsChan {
		if res.MonthlyCost == 0 {
			res.MonthlyCost = EstimateCost(res.Service, res.Type, res.Size)
		}
		results = append(results, res)
	}

	return results
}

func (p *Provider) ScanAll(ctx context.Context, conf scanner.AuditConfig) ([]scanner.Resource, error) {
	regions := conf.Regions
	
	// If no regions specified, use current region
	if len(regions) == 0 {
		regions = []string{p.region}
	}

	var allResults []scanner.Resource
	var mu sync.Mutex

	var wg sync.WaitGroup
	for _, region := range regions {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			results := p.scanRegion(ctx, r, conf)
			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()
		}(region)
	}

	wg.Wait()
	return allResults, nil
}