package computing

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type EKSScanner struct {
	client *eks.Client
}

func NewEKSScanner(cfg aws.Config) *EKSScanner {
	return &EKSScanner{client: eks.NewFromConfig(cfg)}
}

func (s *EKSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, err
	}
	var res []scanner.Resource
	for _, clusterName := range out.Clusters {
		desc, err := s.client.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(clusterName)})
		if err != nil {
			continue
		}
		
		tags := desc.Cluster.Tags
		if scanner.MatchesRule(tags, rule) {
			res = append(res, scanner.Resource{
				ID:   clusterName,
				Type: "👻 [EKS Cluster]",
				Tags: tags,
			})
		}
	}
	return res, nil
}
