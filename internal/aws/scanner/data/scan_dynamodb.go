package data

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type DynamoDBScanner struct {
	Client *dynamodb.Client
}

func NewDynamoDBScanner(cfg aws.Config) *DynamoDBScanner {
	return &DynamoDBScanner{Client: dynamodb.NewFromConfig(cfg)}
}

func (s *DynamoDBScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.ListTables(ctx, &dynamodb.ListTablesInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, tableName := range out.TableNames {
		risk := "SAFE"
		info := ""

		// Check Backups
		desc, err := s.Client.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
			TableName: &tableName,
		})
		
		if err == nil {
			cb := desc.ContinuousBackupsDescription
			if cb.PointInTimeRecoveryDescription == nil || 
			   cb.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == "DISABLED" {
				risk = "MEDIUM"
				info = "Backups Disabled"
			}
		}

		if rule.ScanMode == "RISK" {
			if risk == "SAFE" || risk == "LOW" { continue }
		}

		tags := map[string]string{}

		if scanner.MatchesRule(tags, rule) {
			results = append(results, scanner.Resource{
				ID:   tableName,
				Type: "DynamoDB Table",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
