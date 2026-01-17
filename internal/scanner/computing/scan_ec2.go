package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	tea "github.com/charmbracelet/bubbletea"
)

func scanEC2(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := ec2.NewFromConfig(cfg)
	regions, err := client.DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(true),
	})
	if err != nil {
		send(p, "EC2: error listing regions: "+err.Error())
		return
	}

	var wg sync.WaitGroup

	for _, r := range regions.Regions {
		if r.RegionName == nil {
			continue
		}
		rName := *r.RegionName

		wg.Add(1)
		go func(region string) {
			defer wg.Done()

			regCfg := cfg.Copy()
			regCfg.Region = region
			regClient := ec2.NewFromConfig(regCfg)

			resp, err := regClient.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
			if err != nil {
				return
			}

			for _, res := range resp.Reservations {
				for _, inst := range res.Instances {
					if inst.State.Name == types.InstanceStateNameTerminated {
						continue
					}

					hasTag := false
					for _, t := range inst.Tags {
						if t.Key != nil && t.Value != nil &&
							*t.Key == conf.TargetKey && *t.Value == conf.TargetVal {
							hasTag = true
							break
						}
					}

					if !hasTag {
						send(p, fmt.Sprintf("EC2: [%s] %s", region, *inst.InstanceId))
					}
				}
			}
		}(rName)
	}

	wg.Wait()
}
