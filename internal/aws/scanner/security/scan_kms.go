package security

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type KMSScanner struct {
	client *kms.Client
}

func NewKMSScanner(cfg aws.Config) *KMSScanner {
	return &KMSScanner{client: kms.NewFromConfig(cfg)}
}

func (s *KMSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {

	out, err := s.client.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		return nil, err
	}

	var res []scanner.Resource
	for _, k := range out.Keys {
		desc, err := s.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
		if err != nil {
			continue
		}
		
		meta := desc.KeyMetadata

		if meta.KeyManager == "CUSTOMER" && meta.KeyState == "Enabled" {
			res = append(res, scanner.Resource{
				ID:   *meta.KeyId,
				Type: "👻 [KMS Key (Customer)]",
				Tags: nil, 
			})
		}
	}
	return res, nil
}
