package aws

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	tea "github.com/charmbracelet/bubbletea"
)

// Msg types to send back to UI
type FoundMsg string
type FinishedMsg struct{}

// Configuration
const (
	SafeTagKey   = "ManagedBy"
	SafeTagValue = "Terraform"
)

// ScanAll runs in a goroutine and pumps messages to the UI program
func ScanAll(p *tea.Program) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		p.Send(FoundMsg("Error loading AWS config: " + err.Error()))
		p.Send(FinishedMsg{})
		return
	}

	var wg sync.WaitGroup

	// 1. Scan EC2- Global Region Scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanEC2(cfg, p)
	}()

	// 2. Scan S3 - Global Service
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanS3(cfg, p)
	}()

	wg.Wait()
	p.Send(FinishedMsg{})
}

func scanEC2(cfg aws.Config, p *tea.Program) {
	client := ec2.NewFromConfig(cfg)

	// Get all regions
	regions, err := client.DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{AllRegions: aws.Bool(true)})
	if err != nil {
		return
	}
	var regionWg sync.WaitGroup

	for _, r := range regions.Regions {
		regionWg.Add(1)
		go func(rName string) {
			defer regionWg.Done()

			// New client per region
			regionalCfg := cfg.Copy()
			regionalCfg.Region = rName
			regClient := ec2.NewFromConfig(regionalCfg)

			resp, err := regClient.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
			if err != nil {
				return
			}

			for _, res := range resp.Reservations {
				for _, inst := range res.Instances {
					if inst.State.Name == types.InstanceStateNameTerminated {
						continue
					}

					// Check Drift
					isManaged := false
					for _, t := range inst.Tags {
						if *t.Key == SafeTagKey && *t.Value == SafeTagValue {
							isManaged = true
						}
					}

					if !isManaged {
						p.Send(FoundMsg(fmt.Sprintf("EC2 Drift: [%s] %s", rName, *inst.InstanceId)))
					}
				}
			}
		}(*r.RegionName)
	}
	regionWg.Wait()
}

func scanS3(cfg aws.Config, p *tea.Program) {
	client := s3.NewFromConfig(cfg)
	resp, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		return
	}

	for _, b := range resp.Buckets {
		// Check if Bucket is Public
		tags, err := client.GetBucketTagging(context.TODO(), &s3.GetBucketTaggingInput{Bucket: b.Name})
		isManaged := false

		if err == nil {
			for _, t := range tags.TagSet {
				if *t.Key == SafeTagKey && *t.Value == SafeTagValue {
					isManaged = true
				}
			}
		}

		if !isManaged {
			p.Send(FoundMsg(fmt.Sprintf("S3 Drift:  %s", *b.Name)))
		}
	}
}
