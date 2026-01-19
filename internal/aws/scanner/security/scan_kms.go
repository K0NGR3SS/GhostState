package security

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type KMSScanner struct {
	Client *kms.Client
}

func NewKMSScanner(cfg aws.Config) *KMSScanner {
	return &KMSScanner{Client: kms.NewFromConfig(cfg)}
}

func (s *KMSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := kms.NewListKeysPaginator(s.Client, &kms.ListKeysInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, k := range out.Keys {
			res := scanner.Resource{
				ID:   aws.ToString(k.KeyId),
				ARN:  aws.ToString(k.KeyArn),
				Type: "KMS Key",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			desc, err := s.Client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
			if err == nil && desc.KeyMetadata != nil {
				meta := desc.KeyMetadata

				if meta.KeyState == "PendingDeletion" {
					res.IsGhost = true
					res.GhostInfo = "Key Pending Deletion"
				}

				if meta.KeyManager == "CUSTOMER" && meta.KeyState == "Enabled" {
					res.IsGhost = true
					res.GhostInfo = "Customer Managed Key (Review Usage)"
				}
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
