package security

import (
	"context"
    "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
    "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type IAMScanner struct {
	Client *iam.Client
}


func NewIAMScanner(cfg aws.Config) *IAMScanner {
    return &IAMScanner{Client: iam.NewFromConfig(cfg)}
}

func (s *IAMScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
    input := &iam.ListUsersInput{}
    out, err := s.Client.ListUsers(ctx, input)
    if err != nil {
        return nil, err
    }

    var results []scanner.Resource
    for _, u := range out.Users {
        res := scanner.Resource{
            ID:   *u.UserName,
            Type: "👻 [IAM User]",
            Tags: convertTagsIAM(u.Tags),
        }
        if scanner.MatchesRule(res.Tags, rule) { 
             results = append(results, res)
        }
    }
    return results, nil
}

func convertTagsIAM(tags []types.Tag) map[string]string {
    m := make(map[string]string)
    for _, t := range tags {
        if t.Key != nil && t.Value != nil {
            m[*t.Key] = *t.Value
        }
    }
    return m
}
