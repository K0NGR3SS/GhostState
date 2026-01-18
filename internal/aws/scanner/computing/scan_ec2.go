package computing

import (
	"context"
	"fmt"
	"sync"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/K0NGR3SS/GhostState/internal/aws/clients"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type EC2Scanner struct {
	baseCfg aws.Config
}

func NewEC2Scanner(cfg aws.Config) *EC2Scanner {
	return &EC2Scanner{baseCfg: cfg}
}

func (s *EC2Scanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	client := clients.NewEC2(s.baseCfg) 
	
	regions, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(true)})
	if err != nil {
		return nil, fmt.Errorf("listing regions: %w", err)
	}

	var mu sync.Mutex
	var resources []scanner.Resource
	var wg sync.WaitGroup

	for _, r := range regions.Regions {
		if r.RegionName == nil { continue }
		region := *r.RegionName

		wg.Add(1)
		go func(reg string) {
			defer wg.Done()

			regCfg := s.baseCfg.Copy()
			regCfg.Region = reg
			regClient := clients.NewEC2(regCfg)

			resp, err := regClient.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
			if err != nil { return }

			for _, res := range resp.Reservations {
				for _, inst := range res.Instances {
					if inst.State.Name == types.InstanceStateNameTerminated { continue }

					tagMap := make(map[string]string)
					for _, t := range inst.Tags {
						if t.Key != nil && t.Value != nil { tagMap[*t.Key] = *t.Value }
					}

					if !scanner.IsCompliant(tagMap, rule) {
						mu.Lock()
						resources = append(resources, scanner.Resource{
							Type: "EC2 Instance",
							ID:   fmt.Sprintf("[%s] %s", reg, *inst.InstanceId),
							ARN:  *inst.InstanceId,
						})
						mu.Unlock()
					}
				}
			}
		}(region)
	}
	wg.Wait()
	return resources, nil
}
