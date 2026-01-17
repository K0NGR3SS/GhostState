package computing

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"ghoststate/internal/scanner"
)

type LambdaScanner struct {
	client *lambda.Client
}

func NewLambdaScanner(cfg aws.Config) *LambdaScanner {
	return &LambdaScanner{
		client: lambda.NewFromConfig(cfg),
	}
}

func (s *LambdaScanner) Scan(ctx context.Context, auditRule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource

	paginator := lambda.NewListFunctionsPaginator(s.client, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Lambda functions: %w", err)
		}

		for _, function := range page.Functions {
			tags, err := s.client.ListTags(ctx, &lambda.ListTagsInput{
				Resource: function.FunctionArn,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to list tags for %s: %w", *function.FunctionName, err)
			}

			if !scanner.IsCompliant(tags.Tags, auditRule) {
				resources = append(resources, scanner.Resource{
					Type: "Lambda Function",
					ID:   *function.FunctionName,
					ARN:  *function.FunctionArn,
				})
			}
		}
	}

	return resources, nil
}