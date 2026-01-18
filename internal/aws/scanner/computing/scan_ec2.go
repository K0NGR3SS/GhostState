package computing

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type EC2Scanner struct {
	Client *ec2.Client
}

func NewEC2Scanner(cfg aws.Config) *EC2Scanner {
	return &EC2Scanner{Client: ec2.NewFromConfig(cfg)}
}

func (s *EC2Scanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			risk := "SAFE"
			info := ""

			if i.State.Name == types.InstanceStateNameStopped {
				risk = "LOW"
				info = "Instance Stopped"
			}

			if i.PublicIpAddress != nil && i.State.Name == types.InstanceStateNameRunning {
				risk = "HIGH"
				info = fmt.Sprintf("Public IP: %s", *i.PublicIpAddress)
			}

			if rule.ScanMode == "RISK" {
				if risk == "SAFE" || risk == "LOW" { continue }
			}
			if rule.ScanMode == "GHOST" {
				if i.State.Name != types.InstanceStateNameStopped { continue }
			}

			tags := make(map[string]string)
			for _, t := range i.Tags {
				if t.Key != nil && t.Value != nil {
					tags[*t.Key] = *t.Value
				}
			}

			if scanner.MatchesRule(tags, rule) {
				results = append(results, scanner.Resource{
					ID:   *i.InstanceId,
					Type: "EC2 Instance",
					Tags: tags,
					Risk: risk,
					Info: info,
				})
			}
		}
	}
	return results, nil
}
