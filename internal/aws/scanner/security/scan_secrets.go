package security

import (
	"context"
	"time"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SecretsScanner struct {
	Client *secretsmanager.Client
}

func NewSecretsScanner(cfg aws.Config) *SecretsScanner {
	return &SecretsScanner{Client: secretsmanager.NewFromConfig(cfg)}
}

func (s *SecretsScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := secretsmanager.NewListSecretsPaginator(s.Client, &secretsmanager.ListSecretsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, secret := range out.SecretList {
			res := scanner.Resource{
				ID:   aws.ToString(secret.Name),
				ARN:  aws.ToString(secret.ARN),
				Type: "Secret",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			for _, t := range secret.Tags {
				if t.Key != nil && t.Value != nil {
					res.Tags[*t.Key] = *t.Value
				}
			}
			
			if secret.LastAccessedDate == nil {
				res.IsGhost = true
				res.GhostInfo = "Never Accessed"
			} else if time.Since(*secret.LastAccessedDate) > 90*24*time.Hour {
				res.IsGhost = true
				res.GhostInfo = "Unused > 90 Days"
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
