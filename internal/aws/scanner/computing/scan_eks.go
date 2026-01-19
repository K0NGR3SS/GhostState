package computing

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

type EKSScanner struct {
	client *eks.Client
}

func NewEKSScanner(cfg aws.Config) *EKSScanner {
	return &EKSScanner{client: eks.NewFromConfig(cfg)}
}

func (s *EKSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := eks.NewListClustersPaginator(s.client, &eks.ListClustersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, clusterName := range page.Clusters {
			desc, err := s.client.DescribeCluster(ctx, &eks.DescribeClusterInput{
				Name: aws.String(clusterName),
			})
			if err != nil || desc.Cluster == nil {
				continue
			}

			res := scanner.Resource{
				ID:   clusterName,
				ARN:  aws.ToString(desc.Cluster.Arn),
				Type: "EKS Cluster",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			if desc.Cluster.Tags != nil {
				for k, v := range desc.Cluster.Tags {
					res.Tags[k] = v
				}
			}

			ng, err1 := s.client.ListNodegroups(ctx, &eks.ListNodegroupsInput{
				ClusterName: aws.String(clusterName),
				MaxResults:  aws.Int32(1),
			})
			fp, err2 := s.client.ListFargateProfiles(ctx, &eks.ListFargateProfilesInput{
				ClusterName: aws.String(clusterName),
				MaxResults:  aws.Int32(1),
			})

			if err1 == nil && err2 == nil && len(ng.Nodegroups) == 0 && len(fp.FargateProfileNames) == 0 {
				res.IsGhost = true
				res.GhostInfo = "No nodegroups/fargate profiles"
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}