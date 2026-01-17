package security

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type ACMScanner struct {
	client *acm.Client
}

func NewACMScanner(cfg aws.Config) *ACMScanner {
	return &ACMScanner{client: acm.NewFromConfig(cfg)}
}

func (s *ACMScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource

	listOut, err := s.client.ListCertificates(ctx, &acm.ListCertificatesInput{})
	if err != nil {
		return nil, fmt.Errorf("listing certificates: %w", err)
	}

	for _, summary := range listOut.CertificateSummaryList {
		if summary.CertificateArn == nil { continue }
		arn := *summary.CertificateArn

		tagOut, err := s.client.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{
			CertificateArn: &arn,
		})
		if err != nil { continue }

		isCompliant := false
		for _, t := range tagOut.Tags {
			if t.Key != nil && t.Value != nil &&
				*t.Key == rule.TargetKey && *t.Value == rule.TargetVal {
				isCompliant = true
				break
			}
		}

		if !isCompliant {

			descOut, err := s.client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: &arn})
			id := arn
			if err == nil && descOut.Certificate != nil {
				id = fmt.Sprintf("%s (%s)", aws.ToString(descOut.Certificate.DomainName), arn)
			}
			
			resources = append(resources, scanner.Resource{
				Type: "ACM Certificate",
				ID:   id,
				ARN:  arn,
			})
		}
	}

	return resources, nil
}