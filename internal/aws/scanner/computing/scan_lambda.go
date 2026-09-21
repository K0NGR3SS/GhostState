package computing

import (
	"context"
	"strings"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

type LambdaScanner struct {
	Client *lambda.Client
}

func NewLambdaScanner(cfg aws.Config) *LambdaScanner {
	return &LambdaScanner{Client: lambda.NewFromConfig(cfg)}
}

func (s *LambdaScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := lambda.NewListFunctionsPaginator(s.Client, &lambda.ListFunctionsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return results, err
		}

		for _, fn := range out.Functions {
			res := scanner.Resource{
				ID:      aws.ToString(fn.FunctionName),
				ARN:     aws.ToString(fn.FunctionArn),
				Service: "Lambda",
				Status:  "Active",
				Type:    "Lambda Function",
				Tags:    map[string]string{},
				Risk:    "SAFE",
			}

			if fn.FunctionArn != nil {
				tout, err := s.Client.ListTags(ctx, &lambda.ListTagsInput{Resource: fn.FunctionArn})
				if err == nil {
					for k, v := range tout.Tags {
						res.Tags[k] = v
					}
				}
			}

			var riskIssues []string
			rt := strings.ToLower(string(fn.Runtime))
			if strings.Contains(rt, "python3.6") ||
				strings.Contains(rt, "python3.7") ||
				strings.Contains(rt, "nodejs12") ||
				strings.Contains(rt, "go1.x") {
				res.Risk = "MEDIUM"
				riskIssues = append(riskIssues, "Deprecated runtime: "+string(fn.Runtime))
			}

			urlPager := lambda.NewListFunctionUrlConfigsPaginator(s.Client, &lambda.ListFunctionUrlConfigsInput{
				FunctionName: fn.FunctionName,
			})
			for urlPager.HasMorePages() {
				urlOut, err := urlPager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, urlConfig := range urlOut.FunctionUrlConfigs {
					if urlConfig.AuthType == types.FunctionUrlAuthTypeNone {
						res.Risk = "HIGH"
						riskIssues = append(riskIssues, "Public Function URL")
						break
					}
				}
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
