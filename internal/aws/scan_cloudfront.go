package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	tea "github.com/charmbracelet/bubbletea"
)

func scanCloudfront(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := cloudfront.NewFromConfig(cfg)

	listOut, err := client.ListDistributions(context.TODO(), &cloudfront.ListDistributionsInput{})
	if err != nil {
		send(p, "CF: error listing distributions: "+err.Error())
		return
	}

	if listOut.DistributionList == nil {
		return
	}

	for _, item := range listOut.DistributionList.Items {
		id := aws.ToString(item.Id)
		domain := aws.ToString(item.DomainName)
		status := aws.ToString(item.Status)
		enabled := item.Enabled
		send(p, fmt.Sprintf("CloudFront: id=%s domain=%s enabled=%t status=%s (Tag check skipped)", id, domain, enabled, status))
	}
}
