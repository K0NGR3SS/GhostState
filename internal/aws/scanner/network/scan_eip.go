package network

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type EIPScanner struct {
	client *ec2.Client
}

func NewEIPScanner(cfg aws.Config) *EIPScanner {
	return &EIPScanner{client: ec2.NewFromConfig(cfg)}
}

func (s *EIPScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	// List all addresses
	out, err := s.client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, err
	}

	var res []scanner.Resource
	for _, addr := range out.Addresses {
		if addr.AssociationId == nil {
			
			tags := make(map[string]string)
			for _, t := range addr.Tags {
				if t.Key != nil && t.Value != nil { tags[*t.Key] = *t.Value }
			}

			if scanner.MatchesRule(tags, rule) {
				ip := "unknown"
				if addr.PublicIp != nil { ip = *addr.PublicIp }
				
				res = append(res, scanner.Resource{
					ID:   ip,
					Type: "👻 [Unused EIP]",
					Tags: tags,
				})
			}
		}
	}
	return res, nil
}
