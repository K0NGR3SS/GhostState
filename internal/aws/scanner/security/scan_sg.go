package security

import (
	"context"
	"fmt"
	"strings"

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

// Map of critical ports and their service names
var criticalPorts = map[int32]string{
	20:    "FTP-Data",
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	1433:  "SQL Server",
	1521:  "Oracle DB",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5984:  "CouchDB",
	6379:  "Redis",
	7001:  "Cassandra",
	8020:  "Hadoop",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	9042:  "Cassandra",
	9200:  "Elasticsearch",
	9300:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
	27018: "MongoDB",
	50070: "Hadoop",
}

// Determine risk level based on port
func getRiskLevel(port int32) string {
	switch port {
	case 22, 3389, 23:
		// Remote access protocols - CRITICAL
		return "CRITICAL"
	case 3306, 5432, 1433, 1521, 27017, 27018, 6379, 9200, 9300, 11211, 5984:
		// Database ports - HIGH
		return "HIGH"
	case 21, 20, 445, 139, 25, 110, 143:
		// Unencrypted or legacy protocols - HIGH
		return "HIGH"
	case 80, 8080, 8888:
		// HTTP ports - MEDIUM (should use HTTPS)
		return "MEDIUM"
	default:
		// Other ports - MEDIUM
		return "MEDIUM"
	}
}

// Check if a port range contains a critical port
func (s *SGScanner) checkCriticalPorts(fromPort, toPort int32) []string {
	var findings []string
	
	// Check each critical port
	for port, service := range criticalPorts {
		if port >= fromPort && port <= toPort {
			findings = append(findings, fmt.Sprintf("%s (%d)", service, port))
		}
	}
	
	return findings
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
			ID:      fmt.Sprintf("%s (%s)", sgName, sgID),
			Service: "Security Group",
			Type:    "Security Group",
			Tags:    map[string]string{},
			Risk:    "SAFE",
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
		var allFindings []string
		highestRisk := "SAFE"

		for _, perm := range sg.IpPermissions {
			openWorld := false
			
			// Check IPv4 ranges
			for _, ipRange := range perm.IpRanges {
				if ipRange.CidrIp != nil && *ipRange.CidrIp == "0.0.0.0/0" {
					openWorld = true
					break
				}
			}
			
			// Check IPv6 ranges (often forgotten!)
			if !openWorld {
				for _, ipv6Range := range perm.Ipv6Ranges {
					if ipv6Range.CidrIpv6 != nil && *ipv6Range.CidrIpv6 == "::/0" {
						openWorld = true
						break
					}
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

			// Special case: all ports open
			if fromPort == 0 && toPort == 65535 {
				allFindings = append(allFindings, "ALL PORTS (0-65535)")
				highestRisk = "CRITICAL"
				continue
			}

			// Check for critical ports in this range
			criticalFound := s.checkCriticalPorts(fromPort, toPort)
			
			if len(criticalFound) > 0 {
				for _, finding := range criticalFound {
					allFindings = append(allFindings, finding)
					
					// Extract port number to determine risk
					var port int32
					fmt.Sscanf(finding, "%*s (%d)", &port)
					portRisk := getRiskLevel(port)
					
					// Update to highest risk level found
					if portRisk == "CRITICAL" {
						highestRisk = "CRITICAL"
					} else if portRisk == "HIGH" && highestRisk != "CRITICAL" {
						highestRisk = "HIGH"
					} else if portRisk == "MEDIUM" && highestRisk == "SAFE" {
						highestRisk = "MEDIUM"
					}
				}
			} else {
				// Non-critical port range open
				allFindings = append(allFindings, fmt.Sprintf("Port %d-%d", fromPort, toPort))
				if highestRisk == "SAFE" {
					highestRisk = "LOW"
				}
			}
		}

		// Update resource with findings
		if len(allFindings) > 0 {
			res.Risk = highestRisk
			
			// Build detailed risk info
			if len(allFindings) <= 3 {
				res.RiskInfo = fmt.Sprintf("Open to World: %s", strings.Join(allFindings, ", "))
			} else {
				// Too many findings, summarize
				res.RiskInfo = fmt.Sprintf("Open to World: %s and %d more ports", 
					strings.Join(allFindings[:3], ", "), 
					len(allFindings)-3)
			}
		}

		if scanner.MatchesRule(res.Tags, rule) {
			results = append(results, res)
		}
	}

	return results, nil
}