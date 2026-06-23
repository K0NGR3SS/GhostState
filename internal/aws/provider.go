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
		if len(conf.Regions) > 0 {
			return conf.Regions, nil
		}
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

func (p *Provider) scanRegion(ctx context.Context, region string, includeGlobal bool, conf scanner.AuditConfig) ([]scanner.Resource, []scanner.ScanError) {
	// Create region-specific config
	regionalCfg := p.cfg.Copy()
	regionalCfg.Region = region

	// Create worker pool with 10 concurrent workers
	workerPool := pool.NewWorkerPool(10)
	workerPool.Start()

	resultsChan := make(chan scanner.Resource, 1000)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var scanErrors []scanner.ScanError

	// Helper function to submit scanner tasks to worker pool
	submit := func(serviceName string, s interface {
		Scan(context.Context, scanner.AuditRule) ([]scanner.Resource, error)
	}) {
		wg.Add(1)
		workerPool.Submit(func(ctx context.Context) error {
			defer wg.Done()
			res, err := s.Scan(ctx, conf.TargetRule)
			if err == nil {
				for _, r := range res {
					r.Region = region // Tag resource with region
					r.AccountID = p.accountID
					resultsChan <- r
				}
			} else {
				errMu.Lock()
				scanErrors = append(scanErrors, scanner.ScanError{
					Service: serviceName,
					Region:  region,
					Error:   err.Error(),
				})
				errMu.Unlock()
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
		res = EnrichResource(res)
		results = append(results, res)
	}

	return results, scanErrors
}

func (p *Provider) ScanAll(ctx context.Context, conf scanner.AuditConfig) ([]scanner.Resource, []scanner.ScanError, error) {
	// Clean expired cache entries before scan
	p.tagCache.CleanExpired()

	regions, err := p.resolveRegions(ctx, conf)
	if err != nil {
		return nil, nil, err
	}
	regions = addUniqueStrings(regions)

	var allResults []scanner.Resource
	var allErrors []scanner.ScanError
	var mu sync.Mutex

	// Scan each region concurrently
	var wg sync.WaitGroup
	for idx, region := range regions {
		includeGlobal := idx == 0 && hasGlobalScanners(conf)
		wg.Add(1)
		go func(r string, global bool) {
			defer wg.Done()
			results, scanErrors := p.scanRegion(ctx, r, global, conf)
			mu.Lock()
			allResults = append(allResults, results...)
			allErrors = append(allErrors, scanErrors...)
			mu.Unlock()
		}(region, includeGlobal)
	}

	wg.Wait()
	return allResults, allErrors, nil
}
