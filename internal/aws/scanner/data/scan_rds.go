package data

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type RDSScanner struct {
	Client *rds.Client
}

func NewRDSScanner(cfg aws.Config) *RDSScanner {
	return &RDSScanner{Client: rds.NewFromConfig(cfg)}
}

func (s *RDSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, db := range out.DBInstances {
		risk := "SAFE"
		info := ""

		if db.PubliclyAccessible != nil && *db.PubliclyAccessible {
			risk = "HIGH"
			info = "Publicly Accessible"
		} else {
			if db.StorageEncrypted == nil || !*db.StorageEncrypted {
				risk = "MEDIUM"
				info = "Unencrypted Storage"
			}
		}

		if rule.ScanMode == "RISK" {
			if risk == "SAFE" || risk == "LOW" { continue }
		}

		tags := map[string]string{}

		if scanner.MatchesRule(tags, rule) {
			results = append(results, scanner.Resource{
				ID:   *db.DBInstanceIdentifier,
				Type: "RDS Instance",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
