package computing

import (
	"context"
	"strings"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type LambdaScanner struct {
	Client *lambda.Client
}

func NewLambdaScanner(cfg aws.Config) *LambdaScanner {
	return &LambdaScanner{Client: lambda.NewFromConfig(cfg)}
}

func (s *LambdaScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, fn := range out.Functions {
		risk := "SAFE"
		info := ""

		rt := string(fn.Runtime)
		if strings.Contains(rt, "python3.6") || strings.Contains(rt, "python3.7") || 
		   strings.Contains(rt, "nodejs12") || strings.Contains(rt, "go1.x") {
			risk = "MEDIUM"
			info = "Deprecated Runtime: " + rt
		}

		if rule.ScanMode == "RISK" {
			if risk == "SAFE" { continue }
		}

		tags := map[string]string{}

		if scanner.MatchesRule(tags, rule) {
			results = append(results, scanner.Resource{
				ID:   *fn.FunctionName,
				Type: "Lambda Function",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
