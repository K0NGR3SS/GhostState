package computing

import (
	"context"
	
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type ECRScanner struct {
	Client *ecr.Client
}

func NewECRScanner(cfg aws.Config) *ECRScanner {
	return &ECRScanner{Client: ecr.NewFromConfig(cfg)}
}

func (s *ECRScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, repo := range out.Repositories {
		risk := "SAFE"
		info := ""

		if repo.ImageScanningConfiguration != nil && !repo.ImageScanningConfiguration.ScanOnPush {
			risk = "LOW"
			info = "Image Scanning Disabled"
		}

		if rule.ScanMode == "RISK" {
			if risk == "SAFE" || risk == "LOW" {
				continue
			}
		}

		tags := make(map[string]string)

		if scanner.MatchesRule(tags, rule) {
			results = append(results, scanner.Resource{
				ID:   *repo.RepositoryName,
				Type: "ECR Repo",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
