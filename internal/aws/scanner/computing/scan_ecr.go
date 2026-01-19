package computing

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

type ECRScanner struct {
	Client *ecr.Client
}

func NewECRScanner(cfg aws.Config) *ECRScanner {
	return &ECRScanner{Client: ecr.NewFromConfig(cfg)}
}

func (s *ECRScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := ecr.NewDescribeRepositoriesPaginator(s.Client, &ecr.DescribeRepositoriesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, repo := range out.Repositories {
			res := scanner.Resource{
				ID:   aws.ToString(repo.RepositoryName),
				ARN:  aws.ToString(repo.RepositoryArn),
				Type: "ECR Repo",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			if repo.RepositoryArn != nil {
				tout, err := s.Client.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{
					ResourceArn: repo.RepositoryArn,
				})
				if err == nil {
					for _, t := range tout.Tags {
						if t.Key != nil && t.Value != nil {
							res.Tags[*t.Key] = *t.Value
						}
					}
				}
			}

			lImg, err := s.Client.ListImages(ctx, &ecr.ListImagesInput{
				RepositoryName: repo.RepositoryName,
				MaxResults:     aws.Int32(1),
			})
			if err == nil && len(lImg.ImageIds) == 0 {
				res.IsGhost = true
				res.GhostInfo = "Empty Repository (Unused)"
			}

			if repo.ImageScanningConfiguration != nil && !repo.ImageScanningConfiguration.ScanOnPush {
				res.Risk = "LOW"
				res.RiskInfo = "Image Scanning Disabled"
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
