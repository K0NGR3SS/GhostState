package network

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type CloudFrontScanner struct {
	Client *cloudfront.Client
}

func NewCloudFrontScanner(cfg aws.Config) *CloudFrontScanner {
	return &CloudFrontScanner{Client: cloudfront.NewFromConfig(cfg)}
}

func (s *CloudFrontScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.ListDistributions(ctx, &cloudfront.ListDistributionsInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	if out.DistributionList != nil {
		for _, d := range out.DistributionList.Items {
			risk := "SAFE"
			info := ""

			if d.WebACLId == nil || *d.WebACLId == "" {
				risk = "MEDIUM"
				info = "No WAF Attached"
			} else if !*d.Enabled {
				risk = "LOW"
				info = "Distribution Disabled"
			}

			if rule.ScanMode == "RISK" {
				if risk == "SAFE" || risk == "LOW" { continue }
			}
			if rule.ScanMode == "GHOST" {
				if *d.Enabled { continue }
			}

			tags := map[string]string{}

			if scanner.MatchesRule(tags, rule) {
				results = append(results, scanner.Resource{
					ID:   *d.DomainName,
					Type: "CloudFront Dist",
					Tags: tags,
					Risk: risk,
					Info: info,
				})
			}
		}
	}
	return results, nil
}
