package data

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type ElastiScanner struct {
	client *elasticache.Client
}

func NewElastiScanner(cfg aws.Config) *ElastiScanner {
	return &ElastiScanner{client: elasticache.NewFromConfig(cfg)}
}

func (s *ElastiScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource

	repOut, err := s.client.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err == nil {
		for _, rg := range repOut.ReplicationGroups {
			if rg.ARN == nil { continue }
			tagOut, err := s.client.ListTagsForResource(ctx, &elasticache.ListTagsForResourceInput{ResourceName: rg.ARN})
			if err != nil { continue }

			tagMap := make(map[string]string)
			for _, t := range tagOut.TagList {
				if t.Key != nil && t.Value != nil { tagMap[*t.Key] = *t.Value }
			}

			if !scanner.IsCompliant(tagMap, rule) {
				resources = append(resources, scanner.Resource{
					Type: "ElastiCache RG",
					ID:   aws.ToString(rg.ReplicationGroupId),
					ARN:  *rg.ARN,
				})
			}
		}
	}
	return resources, nil
}
