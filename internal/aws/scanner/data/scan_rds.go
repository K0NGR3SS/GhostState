package data

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/K0NGR3SS/GhostState/internal/aws/clients"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type RDSScanner struct {
	client *rds.Client
}

func NewRDSScanner(cfg aws.Config) *RDSScanner {
	return &RDSScanner{client: clients.NewRDS(cfg)}
}

func (s *RDSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource

	instOut, err := s.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err == nil {
		for _, db := range instOut.DBInstances {
			tagOut, err := s.client.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{ResourceName: db.DBInstanceArn})
			if err != nil { continue }
			
			tagMap := make(map[string]string)
			for _, t := range tagOut.TagList {
				if t.Key != nil && t.Value != nil { tagMap[*t.Key] = *t.Value }
			}

			if !scanner.IsCompliant(tagMap, rule) {
				resources = append(resources, scanner.Resource{
					Type: "RDS Instance",
					ID:   aws.ToString(db.DBInstanceIdentifier),
					ARN:  aws.ToString(db.DBInstanceArn),
				})
			}
		}
	}

	clOut, err := s.client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err == nil {
		for _, cl := range clOut.DBClusters {
			tagOut, err := s.client.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{ResourceName: cl.DBClusterArn})
			if err != nil { continue }

			tagMap := make(map[string]string)
			for _, t := range tagOut.TagList {
				if t.Key != nil && t.Value != nil { tagMap[*t.Key] = *t.Value }
			}

			if !scanner.IsCompliant(tagMap, rule) {
				resources = append(resources, scanner.Resource{
					Type: "RDS Cluster",
					ID:   aws.ToString(cl.DBClusterIdentifier),
					ARN:  aws.ToString(cl.DBClusterArn),
				})
			}
		}
	}

	return resources, nil
}
