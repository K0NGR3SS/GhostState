package network

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
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
	for _, addr := range out.Addresses {
		risk := "SAFE"
		info := ""
		if addr.AssociationId == nil {
			risk = "LOW"
			info = "Unused IP (Wasting Cost)"
		}

		if rule.ScanMode == "RISK" {
			continue 
		}
		if rule.ScanMode == "GHOST" {
			if risk == "SAFE" { continue }
		}

		tags := make(map[string]string)
		for _, t := range addr.Tags {
			if t.Key != nil && t.Value != nil { tags[*t.Key] = *t.Value }
		}

		if scanner.MatchesRule(tags, rule) {
			results = append(results, scanner.Resource{
				ID:   *addr.PublicIp,
				Type: "Elastic IP",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
