package security

import (
	"context"
	"fmt"
	"strings"
	"time"

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
			return results, err
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

				desc, err := s.Client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
					CertificateArn: cert.CertificateArn,
				})
				if err == nil && desc.Certificate != nil {
					var riskIssues []string
					res.Status = string(desc.Certificate.Status)
					if desc.Certificate.NotAfter != nil {
						daysLeft := int(time.Until(*desc.Certificate.NotAfter).Hours() / 24)
						res.Tags["ExpiresInDays"] = fmt.Sprintf("%d", daysLeft)
						if daysLeft < 0 {
							res.Risk = "HIGH"
							riskIssues = append(riskIssues, "Certificate Expired")
						} else if daysLeft <= 30 {
							res.Risk = "HIGH"
							riskIssues = append(riskIssues, fmt.Sprintf("Certificate Expires in %d Days", daysLeft))
						} else if daysLeft <= 60 {
							res.Risk = "MEDIUM"
							riskIssues = append(riskIssues, fmt.Sprintf("Certificate Expires in %d Days", daysLeft))
						}
					}
					keyAlgorithm := strings.ToLower(string(desc.Certificate.KeyAlgorithm))
					if strings.Contains(keyAlgorithm, "rsa_1024") || strings.Contains(keyAlgorithm, "rsa-1024") {
						if res.Risk == "SAFE" {
							res.Risk = "HIGH"
						}
						riskIssues = append(riskIssues, "RSA key length below 2048 bits")
					}
					if len(riskIssues) > 0 {
						res.RiskInfo = strings.Join(riskIssues, "; ")
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
