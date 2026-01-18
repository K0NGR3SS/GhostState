package computing

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type ECSScanner struct {
	Client *ecs.Client
}

func NewECSScanner(cfg aws.Config) *ECSScanner {
	return &ECSScanner{Client: ecs.NewFromConfig(cfg)}
}

func (s *ECSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.ListClusters(ctx, &ecs.ListClustersInput{})
	if err != nil {
		return nil, err
	}
	if len(out.ClusterArns) == 0 {
		return nil, nil
	}

	desc, err := s.Client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
		Clusters: out.ClusterArns,
	})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, c := range desc.Clusters {
		risk := "SAFE"
		info := ""

		if c.RegisteredContainerInstancesCount == 0 && c.RunningTasksCount == 0 {
			risk = "LOW"
			info = "Empty Cluster (No Instances/Tasks)"
		}

		if rule.ScanMode == "RISK" {
			if risk == "SAFE" || risk == "LOW" { continue }
		}
		if rule.ScanMode == "GHOST" {
			if risk == "SAFE" { continue }
		}

		tags := make(map[string]string)
		for _, t := range c.Tags {
			if t.Key != nil && t.Value != nil { tags[*t.Key] = *t.Value }
		}

		if scanner.MatchesRule(tags, rule) {
			results = append(results, scanner.Resource{
				ID:   *c.ClusterName,
				Type: "ECS Cluster",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
