package data

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/K0NGR3SS/GhostState/internal/aws/clients"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type DynamoDBScanner struct {
	client    *dynamodb.Client
	accountID string
	region    string
}

func NewDynamoDBScanner(cfg aws.Config, accountID, region string) *DynamoDBScanner {
	return &DynamoDBScanner{
		client:    clients.NewDynamoDB(cfg),
		accountID: accountID,
		region:    region,
	}
}

func (s *DynamoDBScanner) Scan(ctx context.Context, auditRule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource

	paginator := dynamodb.NewListTablesPaginator(s.client, &dynamodb.ListTablesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list DynamoDB tables: %w", err)
		}

		for _, tableName := range page.TableNames {
			tableArn := fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s", s.region, s.accountID, tableName)
			
			tags, err := s.client.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{
				ResourceArn: aws.String(tableArn),
			})
			if err != nil { continue }

			tagMap := make(map[string]string)
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					tagMap[*t.Key] = *t.Value
				}
			}

			if !scanner.IsCompliant(tagMap, auditRule) {
				resources = append(resources, scanner.Resource{
					Type: "DynamoDB Table",
					ID:   tableName,
					ARN:  tableArn,
				})
			}
		}
	}

	return resources, nil
}
