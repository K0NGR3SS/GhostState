package data

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

type RDSScanner struct {
	Client *rds.Client
}

func NewRDSScanner(cfg aws.Config) *RDSScanner {
	return &RDSScanner{Client: rds.NewFromConfig(cfg)}
}

func (s *RDSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := rds.NewDescribeDBInstancesPaginator(s.Client, &rds.DescribeDBInstancesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, db := range out.DBInstances {
			res := scanner.Resource{
				ID:   aws.ToString(db.DBInstanceIdentifier),
				Type: "RDS Instance",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			if db.DBInstanceArn != nil {
				tout, err := s.Client.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{
					ResourceName: db.DBInstanceArn,
				})
				if err == nil {
					for _, t := range tout.TagList {
						if t.Key != nil && t.Value != nil {
							res.Tags[*t.Key] = *t.Value
						}
					}
				}
			}

			if db.PubliclyAccessible != nil && *db.PubliclyAccessible {
				res.Risk = "HIGH"
				res.RiskInfo = "Publicly Accessible"
			} else if db.StorageEncrypted == nil || !*db.StorageEncrypted {
				res.Risk = "MEDIUM"
				res.RiskInfo = "Unencrypted Storage"
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
