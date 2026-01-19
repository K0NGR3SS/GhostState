package security

import (
	"context"
	"fmt"
	"time"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type IAMScanner struct {
	Client *iam.Client
}

func NewIAMScanner(cfg aws.Config) *IAMScanner {
	return &IAMScanner{Client: iam.NewFromConfig(cfg)}
}

func (s *IAMScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, u := range out.Users {
		res := scanner.Resource{
			ID:   aws.ToString(u.UserName),
			Type: "IAM User",
			Tags: map[string]string{},
			Risk: "SAFE",
		}
		for _, t := range u.Tags {
			if t.Key != nil && t.Value != nil {
				res.Tags[*t.Key] = *t.Value
			}
		}

		if u.PasswordLastUsed != nil {
			daysSince := int(time.Since(*u.PasswordLastUsed).Hours() / 24)
			if daysSince > 90 {
				res.Risk = "MEDIUM"
				res.RiskInfo = fmt.Sprintf("Stale Password (%d days)", daysSince)
			}
		} else {
			res.IsGhost = true
			res.GhostInfo = "No Console Login"
		}

		if scanner.MatchesRule(res.Tags, rule) {
			results = append(results, res)
		}
	}

	return results, nil
}
