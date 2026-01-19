package network

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type EIPScanner struct {
	Client *ec2.Client
}

func NewEIPScanner(cfg aws.Config) *EIPScanner {
	return &EIPScanner{Client: ec2.NewFromConfig(cfg)}
}

func (s *EIPScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, a := range out.Addresses {
		res := scanner.Resource{
			ID:   aws.ToString(a.PublicIp),
			Type: "Elastic IP",
			Tags: map[string]string{},
			Risk: "SAFE",
		}

		for _, t := range a.Tags {
			if t.Key != nil && t.Value != nil {
				res.Tags[*t.Key] = *t.Value
			}
		}

		if a.AssociationId == nil {
			res.IsGhost = true
			res.GhostInfo = "Unassociated EIP"
		}

		if scanner.MatchesRule(res.Tags, rule) {
			results = append(results, res)
		}
	}

	return results, nil
}
