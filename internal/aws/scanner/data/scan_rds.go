package data

import (
	"context"
	"strings"

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
			size := float64(0)
			if db.AllocatedStorage != nil {
				size = float64(*db.AllocatedStorage)
			}

			res := scanner.Resource{
				ID:      aws.ToString(db.DBInstanceIdentifier),
				Service: "RDS",
				Type:    aws.ToString(db.DBInstanceClass),
				Size:    size,
				Status:  aws.ToString(db.DBInstanceStatus),
				Tags:    map[string]string{},
				Risk:    "SAFE",
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

			var riskIssues []string
			if db.PubliclyAccessible != nil && *db.PubliclyAccessible {
				res.Risk = "HIGH"
				riskIssues = append(riskIssues, "Publicly Accessible")
			}
			if db.StorageEncrypted == nil || !*db.StorageEncrypted {
				if res.Risk == "SAFE" {
					res.Risk = "MEDIUM"
				}
				riskIssues = append(riskIssues, "Unencrypted Storage")
			}
			if db.BackupRetentionPeriod == nil || *db.BackupRetentionPeriod == 0 {
				if res.Risk == "SAFE" {
					res.Risk = "MEDIUM"
				}
				riskIssues = append(riskIssues, "Automated Backups Disabled")
			}
			if db.DeletionProtection == nil || !*db.DeletionProtection {
				if res.Risk == "SAFE" {
					res.Risk = "LOW"
				}
				riskIssues = append(riskIssues, "Deletion Protection Disabled")
			}
			if len(riskIssues) > 0 {
				res.RiskInfo = strings.Join(riskIssues, "; ")
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
