package network

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/K0NGR3SS/GhostState/internal/aws/clients"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type VPCScanner struct {
	client *ec2.Client
}

func NewVPCScanner(cfg aws.Config) *VPCScanner {
	// VPC uses EC2 client
	return &VPCScanner{
		client: clients.NewVPC(cfg), 
	}
}

func (s *VPCScanner) Scan(ctx context.Context, auditRule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource

	vpcs, err := s.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe vpcs: %w", err)
	}
	for _, vpc := range vpcs.Vpcs {
		if !s.isCompliant(vpc.Tags, auditRule) {
			resources = append(resources, s.toResource("VPC", *vpc.VpcId))
		}
	}

	subnets, err := s.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe subnets: %w", err)
	}
	for _, subnet := range subnets.Subnets {
		if !s.isCompliant(subnet.Tags, auditRule) {
			resources = append(resources, s.toResource("Subnet", *subnet.SubnetId))
		}
	}

	igws, err := s.client.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe igws: %w", err)
	}
	for _, igw := range igws.InternetGateways {
		if !s.isCompliant(igw.Tags, auditRule) {
			resources = append(resources, s.toResource("Internet Gateway", *igw.InternetGatewayId))
		}
	}

	natPaginator := ec2.NewDescribeNatGatewaysPaginator(s.client, &ec2.DescribeNatGatewaysInput{})
	for natPaginator.HasMorePages() {
		page, err := natPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe nat gateways: %w", err)
		}
		for _, nat := range page.NatGateways {
			if !s.isCompliant(nat.Tags, auditRule) {
				resources = append(resources, s.toResource("NAT Gateway", *nat.NatGatewayId))
			}
		}
	}

	return resources, nil
}

func (s *VPCScanner) isCompliant(ec2Tags []types.Tag, rule scanner.AuditRule) bool {
	tagMap := make(map[string]string)
	for _, t := range ec2Tags {
		if t.Key != nil && t.Value != nil {
			tagMap[*t.Key] = *t.Value
		}
	}
	return scanner.IsCompliant(tagMap, rule)
}

func (s *VPCScanner) toResource(resType, id string) scanner.Resource {
	return scanner.Resource{
		Type: resType,
		ID:   id,
		ARN:  id,
	}
}
