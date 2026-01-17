package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	tea "github.com/charmbracelet/bubbletea"
)

func scanACM(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := acm.NewFromConfig(cfg)

	listOut, err := client.ListCertificates(context.TODO(), &acm.ListCertificatesInput{})
	if err != nil {
		send(p, "ACM: error listing certificates: "+err.Error())
		return
	}

	for _, certSummary := range listOut.CertificateSummaryList {
		if certSummary.CertificateArn == nil {
			continue
		}
		arn := *certSummary.CertificateArn

		descOut, err := client.DescribeCertificate(context.TODO(), &acm.DescribeCertificateInput{
			CertificateArn: &arn,
		})
		if err != nil || descOut.Certificate == nil {
			continue
		}

		cert := descOut.Certificate
		domain := aws.ToString(cert.DomainName)
		issuer := aws.ToString(cert.Issuer)
		status := cert.Status
		notAfter := cert.NotAfter
		inUseBy := cert.InUseBy

		hasTag := false
		tagOut, err := client.ListTagsForCertificate(context.TODO(), &acm.ListTagsForCertificateInput{
			CertificateArn: &arn,
		})
		if err == nil {
			for _, t := range tagOut.Tags {
				if t.Key != nil && t.Value != nil &&
					*t.Key == conf.TargetKey && *t.Value == conf.TargetVal {
					hasTag = true
					break
				}
			}
		}

		if !hasTag {
			expStr := "unknown"
			if notAfter != nil {
				expStr = notAfter.UTC().Format("2006-01-02")
			}
			inUseFlag := len(inUseBy) > 0

			send(p, fmt.Sprintf(
				"ACM: arn=%s domain=%s status=%s expires=%s inUse=%t issuer=%s",
				arn, domain, status, expStr, inUseFlag, issuer,
			))
		}
	}
}
