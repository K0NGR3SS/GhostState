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

type FoundMsg string
type FinishedMsg struct{}

type AuditConfig struct {
	ScanEC2   bool
	ScanS3    bool
	Mode      string
	TargetKey string
	TargetVal string
}

func ScanAll(p *tea.Program, conf AuditConfig) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		p.Send(FoundMsg("Error: " + err.Error()))
		p.Send(FinishedMsg{})
		return
	}

	var wg sync.WaitGroup

	if conf.ScanEC2 {
		wg.Add(1)
		go func() { defer wg.Done(); scanEC2(cfg, p, conf) }()
	}

	if conf.ScanS3 {
		wg.Add(1)
		go func() { defer wg.Done(); scanS3(cfg, p, conf) }()
	}

	wg.Wait()
	p.Send(FinishedMsg{})
}

func scanEC2(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := ec2.NewFromConfig(cfg)
	regions, _ := client.DescribeRegions(context.TODO(), &ec2.DescribeRegionsInput{AllRegions: aws.Bool(true)})

	var wg sync.WaitGroup
	for _, r := range regions.Regions {
		wg.Add(1)
		go func(rName string) {
			defer wg.Done()
			regCfg := cfg.Copy()
			regCfg.Region = rName
			regClient := ec2.NewFromConfig(regCfg)
			
			resp, err := regClient.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
			if err != nil { return }

			for _, res := range resp.Reservations {
				for _, inst := range res.Instances {
					if inst.State.Name == types.InstanceStateNameTerminated { continue }

					hasTag := false
					for _, t := range inst.Tags {
						if *t.Key == conf.TargetKey && *t.Value == conf.TargetVal {
							hasTag = true
						}
					}
					
					if !hasTag {
						p.Send(FoundMsg(fmt.Sprintf("EC2: [%s] %s", rName, *inst.InstanceId)))
					}
				}
			}
		}(*r.RegionName)
	}
	wg.Wait()
}

func scanS3(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := s3.NewFromConfig(cfg)
	resp, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil { return }

	for _, b := range resp.Buckets {
		tags, err := client.GetBucketTagging(context.TODO(), &s3.GetBucketTaggingInput{Bucket: b.Name})
		hasTag := false
		
		if err == nil {
			for _, t := range tags.TagSet {
				if *t.Key == conf.TargetKey && *t.Value == conf.TargetVal {
					hasTag = true
				}
			}
		}

		if !hasTag {
			p.Send(FoundMsg(fmt.Sprintf("S3:  %s", *b.Name)))
		}
	}
}
