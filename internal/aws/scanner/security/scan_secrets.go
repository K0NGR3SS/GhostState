package security

import (
	"context"
	"time"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type SecretsScanner struct {
	client *secretsmanager.Client
}

func NewSecretsScanner(cfg aws.Config) *SecretsScanner {
	return &SecretsScanner{client: secretsmanager.NewFromConfig(cfg)}
}

func (s *SecretsScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return nil, err
	}
	var res []scanner.Resource
	for _, secret := range out.SecretList {

		isGhost := false
		if secret.LastAccessedDate == nil {
			isGhost = true
		} else if time.Since(*secret.LastAccessedDate) > 90*24*time.Hour {
			isGhost = true
		}

		if isGhost {
			tags := make(map[string]string)
			for _, t := range secret.Tags {
				if t.Key != nil && t.Value != nil { tags[*t.Key] = *t.Value }
			}
			if scanner.MatchesRule(tags, rule) {
				res = append(res, scanner.Resource{
					ID:   *secret.Name,
					Type: "👻 [Secret]",
					Tags: tags,
				})
			}
		}
	}
	return res, nil
}
