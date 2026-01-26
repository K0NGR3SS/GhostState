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
			ID:      aws.ToString(u.UserName),
			Service: "IAM",
			Type:    "IAM User",
			Tags:    map[string]string{},
			Risk:    "SAFE",
		}

		for _, t := range u.Tags {
			if t.Key != nil && t.Value != nil {
				res.Tags[*t.Key] = *t.Value
			}
		}

		var riskIssues []string
		highestRisk := "SAFE"

		// Check password age
		if u.PasswordLastUsed != nil {
			daysSince := int(time.Since(*u.PasswordLastUsed).Hours() / 24)
			if daysSince > 90 {
				riskIssues = append(riskIssues, fmt.Sprintf("Stale Password (%d days)", daysSince))
				highestRisk = "MEDIUM"
			}
		} else {
			res.IsGhost = true
			res.GhostInfo = "No Console Login"
		}

		// Check access keys
		accessKeys, err := s.Client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: u.UserName,
		})
		if err == nil {
			for _, key := range accessKeys.AccessKeyMetadata {
				if key.CreateDate != nil {
					daysSince := int(time.Since(*key.CreateDate).Hours() / 24)
					if daysSince > 90 {
						riskIssues = append(riskIssues, fmt.Sprintf("Access Key %s is %d days old", aws.ToString(key.AccessKeyId), daysSince))
						highestRisk = "HIGH"
					}
				}

				// Check for inactive keys
				if key.Status == "Inactive" {
					res.IsGhost = true
					if res.GhostInfo == "" {
						res.GhostInfo = fmt.Sprintf("Inactive Access Key: %s", aws.ToString(key.AccessKeyId))
					} else {
						res.GhostInfo += fmt.Sprintf("; Inactive Key: %s", aws.ToString(key.AccessKeyId))
					}
				}
			}

			// Check for multiple access keys (security concern)
			if len(accessKeys.AccessKeyMetadata) > 1 {
				riskIssues = append(riskIssues, fmt.Sprintf("%d Access Keys (recommend 1)", len(accessKeys.AccessKeyMetadata)))
				if highestRisk == "SAFE" {
					highestRisk = "LOW"
				}
			}
		}

		// Check MFA status
		mfaDevices, err := s.Client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: u.UserName,
		})
		if err == nil && len(mfaDevices.MFADevices) == 0 {
			riskIssues = append(riskIssues, "MFA Not Enabled")
			if highestRisk == "SAFE" || highestRisk == "LOW" {
				highestRisk = "MEDIUM"
			}
		}

		// Set final risk level and info
		res.Risk = highestRisk
		if len(riskIssues) > 0 {
			res.RiskInfo = riskIssues[0]
			if len(riskIssues) > 1 {
				for i := 1; i < len(riskIssues) && i < 3; i++ { // Limit to 3 issues for readability
					res.RiskInfo += "; " + riskIssues[i]
				}
				if len(riskIssues) > 3 {
					res.RiskInfo += fmt.Sprintf(" +%d more issues", len(riskIssues)-3)
				}
			}
		}

		if scanner.MatchesRule(res.Tags, rule) {
			results = append(results, res)
		}
	}

	return results, nil
}