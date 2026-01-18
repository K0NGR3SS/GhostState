package security

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type SGScanner struct {
	Client *ec2.Client
}

func NewSGScanner(cfg aws.Config) *SGScanner {
	return &SGScanner{Client: ec2.NewFromConfig(cfg)}
}

func (s *SGScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, sg := range out.SecurityGroups {
		risk := "SAFE"
		info := ""

		// Check Ingress Rules
		for _, perm := range sg.IpPermissions {
			// Check for 0.0.0.0/0 (Open to World)
			openWorld := false
			for _, ipRange := range perm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
					openWorld = true
					break
				}
			}

			if openWorld {
				fromPort := int32(0)
				if perm.FromPort != nil {
					fromPort = *perm.FromPort
				}
				toPort := int32(65535)
				if perm.ToPort != nil {
					toPort = *perm.ToPort
				}

				// Check specific dangerous ports
				if (fromPort <= 22 && toPort >= 22) {
					risk = "CRITICAL"
					info = "SSH Open to World"
				} else if (fromPort <= 3389 && toPort >= 3389) {
					risk = "CRITICAL"
					info = "RDP Open to World"
				} else if (fromPort <= 80 && toPort >= 80) || (fromPort <= 443 && toPort >= 443) {
					// Web ports open is usually intentional, but we flag it as LOW for visibility
					if risk == "SAFE" {
						risk = "LOW"
						info = "Public Web Access"
					}
				} else {
					// Other open ports
					if risk == "SAFE" || risk == "LOW" {
						risk = "MEDIUM"
						info = fmt.Sprintf("Port %d-%d Open to World", fromPort, toPort)
					}
				}
			}
		}

		// --- MODE FILTERING ---
		// If Mode is RISK, skip SAFE and LOW items
		if rule.ScanMode == "RISK" {
			if risk == "SAFE" || risk == "LOW" {
				continue
			}
		}
		// If Mode is GHOST, we typically look for "Unused" or "Low" risk anomalies.
		// For SG, we might consider "LOW" (Public Web) interesting, or just skip SAFE.
		if rule.ScanMode == "GHOST" {
			if risk == "SAFE" {
				continue
			}
		}

		tags := make(map[string]string)
		for _, t := range sg.Tags {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}

		if scanner.MatchesRule(tags, rule) {
			// Clean Type String - Let the UI handle the Emojis and Info text!
			results = append(results, scanner.Resource{
				ID:   fmt.Sprintf("%s (%s)", *sg.GroupName, *sg.GroupId),
				Type: "Security Group",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
