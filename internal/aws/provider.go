package aws

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/K0NGR3SS/GhostState/internal/aws/cache"
	"github.com/K0NGR3SS/GhostState/internal/aws/pool"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/computing"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/data"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/monitoring"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/network"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/security"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Provider struct {
	cfg       aws.Config
	accountID string
	region    string
	tagCache  *cache.TagCache
}

func NewProvider(ctx context.Context, cfg aws.Config) (*Provider, error) {
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS identity: %w", err)
	}

	return &Provider{
		cfg:       cfg,
		accountID: aws.ToString(identity.Account),
		region:    cfg.Region,
		tagCache:  cache.NewTagCache(5 * time.Minute),
	}, nil
}

func hasGlobalScanners(conf scanner.AuditConfig) bool {
	return conf.ScanS3 || conf.ScanCloudfront || conf.ScanRoute53 || conf.ScanIAM
}

func (p *Provider) resolveRegions(ctx context.Context, conf scanner.AuditConfig) ([]string, error) {
	switch conf.RegionMode {
	case scanner.RegionModeAll:
		regions, err := p.GetAllRegions(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list enabled regions: %w", err)
		}
		return regions, nil
	case scanner.RegionModeCustom:
		regions := addUniqueStrings(conf.Regions)
		if len(regions) == 0 {
			return nil, fmt.Errorf("custom region scope requires at least one region")
		}
		return regions, nil
	}

	if len(conf.Regions) > 0 {
		return conf.Regions, nil
	}
	if p.region != "" {
		return []string{p.region}, nil
	}
	return []string{"us-east-1"}, nil
}

func addUniqueStrings(items []string, additions ...string) []string {
	seen := make(map[string]bool, len(items)+len(additions))
	var result []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		result = append(result, item)
	}
	for _, item := range additions {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		result = append(result, item)
	}
	return result
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

func (p *Provider) scanRegion(ctx context.Context, region string, includeGlobal bool, conf scanner.AuditConfig, progress ScanProgress) ([]scanner.Resource, []scanner.ScanError) {
	// Create region-specific config
	regionalCfg := p.cfg.Copy()
	regionalCfg.Region = region

	// Create worker pool with 10 concurrent workers
	workerPool := pool.NewWorkerPool(ctx, 10)
	workerPool.Start()

	var mu sync.Mutex
	var results []scanner.Resource
	var scanErrors []scanner.ScanError

	submit := func(serviceName string, s scanner.Scanner) {
		workerPool.Submit(func(ctx context.Context) error {
			res, err := s.Scan(ctx, conf.TargetRule)
			// A failed later page must not discard resources already discovered.
			mu.Lock()
			defer mu.Unlock()
			for _, r := range res {
				if r.Region == "" {
					r.Region = region
				}
				r.AccountID = p.accountID
				if r.MonthlyCost == 0 {
					r.MonthlyCost = EstimateCost(r.Service, r.Type, r.Size)
				}
				r = EnrichResource(r)
				results = append(results, r)
				if progress.Resource != nil {
					progress.Resource(r)
				}
			}
			if err != nil {
				scanErr := scanner.ScanError{Service: serviceName, Region: region, Error: err.Error()}
				scanErrors = append(scanErrors, scanErr)
				if progress.Error != nil {
					progress.Error(scanErr)
				}
			}
			return nil
		})
	}

	// --- Computing ---
	if conf.ScanEC2 {
		submit("EC2", computing.NewEC2Scanner(regionalCfg))
	}
	if conf.ScanECS {
		submit("ECS", computing.NewECSScanner(regionalCfg))
	}
	if conf.ScanLambda {
		submit("Lambda", computing.NewLambdaScanner(regionalCfg))
	}
	if conf.ScanEKS {
		submit("EKS", computing.NewEKSScanner(regionalCfg))
	}
	if conf.ScanECR {
		submit("ECR", computing.NewECRScanner(regionalCfg))
	}

	// --- Data ---
	if conf.ScanS3 && includeGlobal {
		// S3 is global, only scan once
		submit("S3", data.NewS3Scanner(regionalCfg))
	}
	if conf.ScanRDS {
		submit("RDS", data.NewRDSScanner(regionalCfg))
	}
	if conf.ScanDynamoDB {
		submit("DynamoDB", data.NewDynamoDBScanner(regionalCfg))
	}
	if conf.ScanElasti {
		submit("ElastiCache", data.NewElastiScanner(regionalCfg))
	}
	if conf.ScanEBS {
		submit("EBS", data.NewEBSScanner(regionalCfg))
	}

	// --- Network ---
	if conf.ScanVPC {
		submit("VPC", network.NewVPCScanner(regionalCfg))
	}
	if conf.ScanCloudfront && includeGlobal {
		// CloudFront is global, only scan once
		submit("CloudFront", network.NewCloudFrontScanner(regionalCfg))
	}
	if conf.ScanEIP {
		submit("Elastic IP", network.NewEIPScanner(regionalCfg))
	}
	if conf.ScanELB {
		submit("ELB", network.NewELBScanner(regionalCfg))
	}
	if conf.ScanRoute53 && includeGlobal {
		// Route53 is global
		submit("Route53", network.NewRoute53Scanner(regionalCfg))
	}

	// --- Security ---
	if conf.ScanACM {
		submit("ACM", security.NewACMScanner(regionalCfg))
	}
	if conf.ScanSecGroups {
		submit("Security Groups", security.NewSGScanner(regionalCfg))
	}
	if conf.ScanIAM && includeGlobal {
		// IAM is global
		submit("IAM", security.NewIAMScanner(regionalCfg))
	}
	if conf.ScanSecrets {
		submit("Secrets Manager", security.NewSecretsScanner(regionalCfg))
	}
	if conf.ScanKMS {
		submit("KMS", security.NewKMSScanner(regionalCfg))
	}
	if conf.ScanCloudTrail {
		submit("CloudTrail", security.NewTrailScanner(regionalCfg))
	}

	// --- Monitoring ---
	if conf.ScanCloudWatch {
		submit("CloudWatch", monitoring.NewCloudWatchScanner(regionalCfg))
	}

	workerPool.Wait()

	return results, scanErrors
}

// ScanProgress callbacks run as services finish. Resource and Error callbacks may
// run concurrently across regions; callers must make them concurrency-safe.
type ScanProgress struct {
	Resource func(scanner.Resource)
	Error    func(scanner.ScanError)
	Regions  func([]string)
}

func (p *Provider) ScanAll(ctx context.Context, conf scanner.AuditConfig) ([]scanner.Resource, []scanner.ScanError, error) {
	return p.ScanAllWithProgress(ctx, conf, ScanProgress{})
}

func (p *Provider) ScanAllWithProgress(ctx context.Context, conf scanner.AuditConfig, progress ScanProgress) ([]scanner.Resource, []scanner.ScanError, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// Clean expired cache entries before scan
	p.tagCache.CleanExpired()

	regions, err := p.resolveRegions(ctx, conf)
	if err != nil {
		return nil, nil, err
	}
	regions = addUniqueStrings(regions)
	if len(regions) == 0 {
		return nil, nil, fmt.Errorf("no enabled regions found")
	}
	if progress.Regions != nil {
		progress.Regions(append([]string(nil), regions...))
	}

	var allResults []scanner.Resource
	var allErrors []scanner.ScanError
	var mu sync.Mutex

	// Bound regional concurrency as well as per-region service concurrency.
	regionPool := pool.NewWorkerPool(ctx, 3)
	for idx, region := range regions {
		includeGlobal := idx == 0 && hasGlobalScanners(conf)
		regionPool.Submit(func(ctx context.Context) error {
			results, scanErrors := p.scanRegion(ctx, region, includeGlobal, conf, progress)
			mu.Lock()
			allResults = append(allResults, results...)
			allErrors = append(allErrors, scanErrors...)
			mu.Unlock()
			return nil
		})
	}

	regionPool.Wait()
	return allResults, allErrors, ctx.Err()
}
