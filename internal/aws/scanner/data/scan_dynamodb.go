package data

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type DynamoDBScanner struct {
	Client *dynamodb.Client
}

func NewDynamoDBScanner(cfg aws.Config) *DynamoDBScanner {
	return &DynamoDBScanner{Client: dynamodb.NewFromConfig(cfg)}
}

func (s *DynamoDBScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := dynamodb.NewListTablesPaginator(s.Client, &dynamodb.ListTablesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, tableName := range out.TableNames {
			res := scanner.Resource{
				ID:   tableName,
				Type: "DynamoDB Table",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			desc, err := s.Client.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
				TableName: &tableName,
			})

			if err == nil {
				cb := desc.ContinuousBackupsDescription
				if cb.PointInTimeRecoveryDescription == nil ||
					cb.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == "DISABLED" {
					res.Risk = "MEDIUM"
					res.RiskInfo = "Backups Disabled"
				}
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
