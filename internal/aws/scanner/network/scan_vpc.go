package network

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type VPCScanner struct {
	Client *ec2.Client
}

func NewVPCScanner(cfg aws.Config) *VPCScanner {
	return &VPCScanner{Client: ec2.NewFromConfig(cfg)}
}

func (s *VPCScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, vpc := range out.Vpcs {
		risk := "SAFE"
		info := ""

		if vpc.IsDefault != nil && *vpc.IsDefault {
			risk = "LOW"
			info = "Default VPC"
		}

		if rule.ScanMode == "RISK" {
			if risk == "SAFE" || risk == "LOW" { continue }
		}

		if rule.ScanMode == "GHOST" {
			if risk == "SAFE" { continue }
		}

		tags := make(map[string]string)
		for _, t := range vpc.Tags {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}

		if scanner.MatchesRule(tags, rule) {
			results = append(results, scanner.Resource{
				ID:   *vpc.VpcId,
				Type: "VPC",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
