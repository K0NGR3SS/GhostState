package network

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

type CloudFrontScanner struct {
	Client *cloudfront.Client
}

func NewCloudFrontScanner(cfg aws.Config) *CloudFrontScanner {
	return &CloudFrontScanner{Client: cloudfront.NewFromConfig(cfg)}
}

func (s *CloudFrontScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := cloudfront.NewListDistributionsPaginator(s.Client, &cloudfront.ListDistributionsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		if out.DistributionList == nil {
			continue
		}

		for _, d := range out.DistributionList.Items {
			res := scanner.Resource{
				ID:   aws.ToString(d.DomainName),
				ARN:  aws.ToString(d.ARN),
				Type: "CloudFront Dist",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			if d.WebACLId == nil || *d.WebACLId == "" {
				res.Risk = "MEDIUM"
				res.RiskInfo = "No WAF Attached"
			}

			if !*d.Enabled {
				res.IsGhost = true
				res.GhostInfo = "Distribution Disabled"
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
