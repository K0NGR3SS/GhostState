package computing

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type ECRScanner struct {
	client *ecr.Client
}

func NewECRScanner(cfg aws.Config) *ECRScanner {
	return &ECRScanner{client: ecr.NewFromConfig(cfg)}
}

func (s *ECRScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
	if err != nil {
		return nil, err
	}
	var res []scanner.Resource
	
	for _, repo := range out.Repositories {
		tags := make(map[string]string)
		res = append(res, scanner.Resource{
			ID:   *repo.RepositoryName,
			Type: fmt.Sprintf("👻 [ECR Repo] (%s)", *repo.RepositoryUri),
			Tags: tags,
		})
	}
	return res, nil
}
