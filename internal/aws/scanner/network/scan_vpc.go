package network

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
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
		res := scanner.Resource{
			ID:   aws.ToString(vpc.VpcId),
			Service: "VPC",
			Type: "VPC",
			Status:  "Available",
			Tags: map[string]string{},
			Risk: "SAFE",
		}

		for _, t := range vpc.Tags {
			if t.Key != nil && t.Value != nil {
				res.Tags[*t.Key] = *t.Value
			}
		}
		if vpc.IsDefault != nil && *vpc.IsDefault {
			res.IsGhost = true
			res.GhostInfo = "Default VPC (Should not be used)"

			res.Risk = "LOW"
			res.RiskInfo = "Default VPC (Public Subnets)"
		}

		if scanner.MatchesRule(res.Tags, rule) {
			results = append(results, res)
		}
	}

	return results, nil
}
