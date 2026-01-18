package security

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/K0NGR3SS/GhostState/internal/aws/clients"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type SGScanner struct {
	client *ec2.Client
}

func NewSGScanner(cfg aws.Config) *SGScanner {
	return &SGScanner{client: clients.NewSecurityGroup(cfg)}
}

func (s *SGScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource

	out, err := s.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing security groups: %w", err)
	}

	for _, sg := range out.SecurityGroups {
		id := aws.ToString(sg.GroupId)
		name := aws.ToString(sg.GroupName)

		tags := make(map[string]string)
		for _, t := range sg.Tags {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}

		if !scanner.IsCompliant(tags, rule) {
			resources = append(resources, scanner.Resource{
				Type: "Security Group",
				ID:   fmt.Sprintf("%s (%s)", name, id),
				ARN:  id,
			})
		}
	}

	return resources, nil
}
