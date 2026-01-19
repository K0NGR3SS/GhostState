package data

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
)

type ElastiScanner struct {
	Client *elasticache.Client
}

func NewElastiScanner(cfg aws.Config) *ElastiScanner {
	return &ElastiScanner{Client: elasticache.NewFromConfig(cfg)}
}

func (s *ElastiScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := elasticache.NewDescribeReplicationGroupsPaginator(s.Client, &elasticache.DescribeReplicationGroupsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, rg := range out.ReplicationGroups {
			res := scanner.Resource{
				ID:   aws.ToString(rg.ReplicationGroupId),
				ARN:  aws.ToString(rg.ARN),
				Type: "ElastiCache Cluster",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			if rg.ARN != nil {
				tout, err := s.Client.ListTagsForResource(ctx, &elasticache.ListTagsForResourceInput{
					ResourceName: rg.ARN,
				})
				if err == nil {
					for _, t := range tout.TagList {
						if t.Key != nil && t.Value != nil {
							res.Tags[*t.Key] = *t.Value
						}
					}
				}
			}

			if len(rg.NodeGroups) == 0 {
				res.IsGhost = true
				res.GhostInfo = "Empty replication group"
			}

			atRest := rg.AtRestEncryptionEnabled != nil && *rg.AtRestEncryptionEnabled
			transit := rg.TransitEncryptionEnabled != nil && *rg.TransitEncryptionEnabled

			if !atRest && !transit {
				res.Risk = "MEDIUM"
				res.RiskInfo = "No encryption enabled"
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
