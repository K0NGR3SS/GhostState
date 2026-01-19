package security

import (
	"context"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

type ACMScanner struct {
	Client *acm.Client
}

func NewACMScanner(cfg aws.Config) *ACMScanner {
	return &ACMScanner{Client: acm.NewFromConfig(cfg)}
}

func (s *ACMScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := acm.NewListCertificatesPaginator(s.Client, &acm.ListCertificatesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, cert := range out.CertificateSummaryList {
			res := scanner.Resource{
				ID:   aws.ToString(cert.DomainName),
				ARN:  aws.ToString(cert.CertificateArn),
				Type: "ACM Certificate",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			if cert.CertificateArn != nil {
				tagOut, err := s.Client.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{
					CertificateArn: cert.CertificateArn,
				})
				if err == nil {
					for _, t := range tagOut.Tags {
						if t.Key != nil && t.Value != nil {
							res.Tags[*t.Key] = *t.Value
						}
					}
				}
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
