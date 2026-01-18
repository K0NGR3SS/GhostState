package network

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/K0NGR3SS/GhostState/internal/aws/clients"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type CloudFrontScanner struct {
	client *cloudfront.Client
}

func NewCloudFrontScanner(cfg aws.Config) *CloudFrontScanner {
	return &CloudFrontScanner{client: clients.NewCloudFront(cfg)}
}

func (s *CloudFrontScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource

	listOut, err := s.client.ListDistributions(ctx, &cloudfront.ListDistributionsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing distributions: %w", err)
	}

	if listOut.DistributionList == nil { return nil, nil }

	for _, item := range listOut.DistributionList.Items {
		tagsOut, err := s.client.ListTagsForResource(ctx, &cloudfront.ListTagsForResourceInput{Resource: item.ARN})
		if err != nil { continue }

		tagMap := make(map[string]string)
		if tagsOut.Tags != nil {
			for _, t := range tagsOut.Tags.Items {
				if t.Key != nil && t.Value != nil { tagMap[*t.Key] = *t.Value }
			}
		}

		if !scanner.IsCompliant(tagMap, rule) {
			resources = append(resources, scanner.Resource{
				Type: "CloudFront Dist",
				ID:   aws.ToString(item.DomainName),
				ARN:  aws.ToString(item.ARN),
			})
		}
	}
	return resources, nil
}
