package security

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
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
		risk := "SAFE"
		info := ""

		if u.PasswordLastUsed != nil {
			daysSince := time.Since(*u.PasswordLastUsed).Hours() / 24
			if daysSince > 90 {
				risk = "MEDIUM"
				info = fmt.Sprintf("Stale Password (%d days)", int(daysSince))
			}
		} else {
			risk = "LOW"
			info = "No Console Login"
		}

		// [FIX] Filter Modes
		if rule.ScanMode == "RISK" {
			if risk == "SAFE" || risk == "LOW" { continue }
		}
		if rule.ScanMode == "GHOST" {
			// Ghost mode implies finding unused things. 
			// "No Console Login" (LOW risk) IS a ghost! Stale password is also kinda ghosty.
			if risk == "SAFE" { continue }
		}

		tags := make(map[string]string)
		for _, t := range u.Tags {
			if t.Key != nil && t.Value != nil { tags[*t.Key] = *t.Value }
		}

		if scanner.MatchesRule(tags, rule) {
			// [FIX] Clean Type String (UI handles the rest)
			results = append(results, scanner.Resource{
				ID:   *u.UserName,
				Type: "IAM User",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
