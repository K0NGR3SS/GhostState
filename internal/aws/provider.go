package aws

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/K0NGR3SS/GhostState/internal/aws/cache"
	"github.com/K0NGR3SS/GhostState/internal/aws/pool"
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
	tagCache  *cache.TagCache
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
		tagCache:  cache.NewTagCache(5 * time.Minute),
	}, nil
}

// GetAllRegions returns all enabled AWS regions
func (p *Provider) GetAllRegions(ctx context.Context) ([]string, error) {
	ec2Client := ec2.NewFromConfig(p.cfg)
	result, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
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

	// Create worker pool with 10 concurrent workers
	workerPool := pool.NewWorkerPool(10)
	workerPool.Start()

	resultsChan := make(chan scanner.Resource, 1000)
	var wg sync.WaitGroup

	// Helper function to submit scanner tasks to worker pool
	submit := func(s interface {
		Scan(context.Context, scanner.AuditRule) ([]scanner.Resource, error)
	}) {
		wg.Add(1)
		workerPool.Submit(func(ctx context.Context) error {
			defer wg.Done()
			res, err := s.Scan(ctx, conf.TargetRule)
			if err == nil {
				for _, r := range res {
					r.Region = region // Tag resource with region
					resultsChan <- r
				}
			}
			return err
		})
	}

	// --- Computing ---
	if conf.ScanEC2 {
		submit(computing.NewEC2Scanner(regionalCfg))
	}
	if conf.ScanECS {
		submit(computing.NewECSScanner(regionalCfg))
	}
	if conf.ScanLambda {
		submit(computing.NewLambdaScanner(regionalCfg))
	}
	if conf.ScanEKS {
		submit(computing.NewEKSScanner(regionalCfg))
	}
	if conf.ScanECR {
		submit(computing.NewECRScanner(regionalCfg))
	}

	// --- Data ---
	if conf.ScanS3 && region == "us-east-1" {
		// S3 is global, only scan once
		submit(data.NewS3Scanner(regionalCfg))
	}
	if conf.ScanRDS {
		submit(data.NewRDSScanner(regionalCfg))
	}
	if conf.ScanDynamoDB {
		submit(data.NewDynamoDBScanner(regionalCfg))
	}
	if conf.ScanElasti {
		submit(data.NewElastiScanner(regionalCfg))
	}
	if conf.ScanEBS {
		submit(data.NewEBSScanner(regionalCfg))
	}

	// --- Network ---
	if conf.ScanVPC {
		submit(network.NewVPCScanner(regionalCfg))
	}
	if conf.ScanCloudfront && region == "us-east-1" {
		// CloudFront is global, only scan once
		submit(network.NewCloudFrontScanner(regionalCfg))
	}
	if conf.ScanEIP {
		submit(network.NewEIPScanner(regionalCfg))
	}
	if conf.ScanELB {
		submit(network.NewELBScanner(regionalCfg))
	}
	if conf.ScanRoute53 && region == "us-east-1" {
		// Route53 is global
		submit(network.NewRoute53Scanner(regionalCfg))
	}

	// --- Security ---
	if conf.ScanACM {
		submit(security.NewACMScanner(regionalCfg))
	}
	if conf.ScanSecGroups {
		submit(security.NewSGScanner(regionalCfg))
	}
	if conf.ScanIAM && region == "us-east-1" {
		// IAM is global
		submit(security.NewIAMScanner(regionalCfg))
	}
	if conf.ScanSecrets {
		submit(security.NewSecretsScanner(regionalCfg))
	}
	if conf.ScanKMS {
		submit(security.NewKMSScanner(regionalCfg))
	}
	if conf.ScanCloudTrail {
		submit(security.NewTrailScanner(regionalCfg))
	}

	// --- Monitoring ---
	if conf.ScanCloudWatch {
		submit(monitoring.NewCloudWatchScanner(regionalCfg))
	}

	// Wait for all scan tasks to complete, then close channels
	go func() {
		wg.Wait()
		workerPool.Wait()
		close(resultsChan)
	}()

	// Collect results
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
	// Clean expired cache entries before scan
	p.tagCache.CleanExpired()

	regions := conf.Regions

	// If no regions specified, use current region
	if len(regions) == 0 {
		regions = []string{p.region}
	}

	var allResults []scanner.Resource
	var mu sync.Mutex

	// Scan each region concurrently
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