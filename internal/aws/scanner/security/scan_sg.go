package security

import (
	"context"
	"fmt"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type SGScanner struct {
	Client *ec2.Client
}

func NewSGScanner(cfg aws.Config) *SGScanner {
	return &SGScanner{Client: ec2.NewFromConfig(cfg)}
}

func (s *SGScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	usedSG := make(map[string]bool)

	eniPager := ec2.NewDescribeNetworkInterfacesPaginator(s.Client, &ec2.DescribeNetworkInterfacesInput{})
	for eniPager.HasMorePages() {
		page, err := eniPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ni := range page.NetworkInterfaces {
			for _, g := range ni.Groups {
				if g.GroupId != nil {
					usedSG[*g.GroupId] = true
				}
			}
		}
	}

	out, err := s.Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, sg := range out.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		sgName := aws.ToString(sg.GroupName)

		res := scanner.Resource{
			ID:   fmt.Sprintf("%s (%s)", sgName, sgID),
			Type: "Security Group",
			Tags: map[string]string{},
			Risk: "SAFE",
		}

		for _, t := range sg.Tags {
			if t.Key != nil && t.Value != nil {
				res.Tags[*t.Key] = *t.Value
			}
		}

		if sgName != "default" && !usedSG[sgID] {
			res.IsGhost = true
			res.GhostInfo = "Unused (not attached to any ENI)"
		}

		// Risk analysis: ingress open to world
		for _, perm := range sg.IpPermissions {
			openWorld := false
			for _, ipRange := range perm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
					openWorld = true
					break
				}
			}
			if !openWorld {
				continue
			}

			fromPort := int32(0)
			if perm.FromPort != nil {
				fromPort = *perm.FromPort
			}
			toPort := int32(65535)
			if perm.ToPort != nil {
				toPort = *perm.ToPort
			}

			if fromPort <= 22 && toPort >= 22 {
				res.Risk = "CRITICAL"
				res.RiskInfo = "SSH Open to World"
			} else if fromPort <= 3389 && toPort >= 3389 {
				res.Risk = "CRITICAL"
				res.RiskInfo = "RDP Open to World"
			} else {
				if res.Risk != "CRITICAL" {
					res.Risk = "MEDIUM"
					res.RiskInfo = fmt.Sprintf("Port %d-%d Open to World", fromPort, toPort)
				}
			}
		}

		if scanner.MatchesRule(res.Tags, rule) {
			results = append(results, res)
		}
	}

	return results, nil
}
