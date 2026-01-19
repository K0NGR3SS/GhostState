package computing

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

type ECSScanner struct {
	Client *ecs.Client
}

func NewECSScanner(cfg aws.Config) *ECSScanner {
	return &ECSScanner{Client: ecs.NewFromConfig(cfg)}
}

func (s *ECSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var clusterArns []string

	p := ecs.NewListClustersPaginator(s.Client, &ecs.ListClustersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		clusterArns = append(clusterArns, page.ClusterArns...)
	}

	if len(clusterArns) == 0 {
		return nil, nil
	}

	var results []scanner.Resource

	for i := 0; i < len(clusterArns); i += 100 {
		end := i + 100
		if end > len(clusterArns) {
			end = len(clusterArns)
		}

		desc, err := s.Client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: clusterArns[i:end],
			Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldTags},
		})
		if err != nil {
			return nil, err
		}

		for _, c := range desc.Clusters {
			res := scanner.Resource{
				ID:   aws.ToString(c.ClusterName),
				ARN:  aws.ToString(c.ClusterArn),
				Type: "ECS Cluster",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			for _, t := range c.Tags {
				if t.Key != nil && t.Value != nil {
					res.Tags[*t.Key] = *t.Value
				}
			}

			if c.RegisteredContainerInstancesCount == 0 && c.RunningTasksCount == 0 {
				res.IsGhost = true
				res.GhostInfo = "Empty cluster (no instances/tasks)"
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}