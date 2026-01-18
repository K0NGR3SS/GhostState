package computing

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/K0NGR3SS/GhostState/internal/aws/clients"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type ECSScanner struct {
	client *ecs.Client
}

func NewECSScanner(cfg aws.Config) *ECSScanner {
	return &ECSScanner{client: clients.NewECS(cfg)}
}

func (s *ECSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource

	listOut, err := s.client.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("listing clusters: %w", err)
	}
	if len(listOut.ClusterArns) == 0 { return nil, nil }

	descOut, err := s.client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: listOut.ClusterArns,
		Include:  []types.ClusterField{types.ClusterFieldTags},
	})
	if err != nil {
		return nil, fmt.Errorf("describing clusters: %w", err)
	}

	for _, cl := range descOut.Clusters {
		tagMap := make(map[string]string)
		for _, t := range cl.Tags {
			if t.Key != nil && t.Value != nil { tagMap[*t.Key] = *t.Value }
		}

		if !scanner.IsCompliant(tagMap, rule) {
			resources = append(resources, scanner.Resource{
				Type: "ECS Cluster",
				ID:   aws.ToString(cl.ClusterName),
				ARN:  aws.ToString(cl.ClusterArn),
			})
		}
	}

	return resources, nil
}
