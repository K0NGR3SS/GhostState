package scanner_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/network"
	"github.com/K0NGR3SS/GhostState/internal/aws/scanner/security"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type mockClient func(*http.Request) (*http.Response, error)

func (f mockClient) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestInventoryPagination(t *testing.T) {
	cases := []struct {
		name          string
		newScanner    func(aws.Config) scanner.Scanner
		first, second string
	}{
		{"VPC", func(c aws.Config) scanner.Scanner { return network.NewVPCScanner(c) },
			`<DescribeVpcsResponse><vpcSet/><nextToken>next</nextToken></DescribeVpcsResponse>`,
			`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-page-two</vpcId></item></vpcSet></DescribeVpcsResponse>`},
		{"SecurityGroups", func(c aws.Config) scanner.Scanner { return security.NewSGScanner(c) },
			`<DescribeSecurityGroupsResponse><securityGroupInfo/><nextToken>next</nextToken></DescribeSecurityGroupsResponse>`,
			`<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-page-two</groupId><groupName>default</groupName></item></securityGroupInfo></DescribeSecurityGroupsResponse>`},
		{"IAM", func(c aws.Config) scanner.Scanner { return security.NewIAMScanner(c) },
			`<ListUsersResponse><ListUsersResult><Users/><IsTruncated>true</IsTruncated><Marker>next</Marker></ListUsersResult></ListUsersResponse>`,
			`<ListUsersResponse><ListUsersResult><Users/><IsTruncated>false</IsTruncated></ListUsersResult></ListUsersResponse>`},
		{"Route53", func(c aws.Config) scanner.Scanner { return network.NewRoute53Scanner(c) },
			`<ListHostedZonesResponse><HostedZones/><IsTruncated>true</IsTruncated><NextMarker>next</NextMarker></ListHostedZonesResponse>`,
			`<ListHostedZonesResponse><HostedZones/><IsTruncated>false</IsTruncated></ListHostedZonesResponse>`},
		{"CloudTrail", func(c aws.Config) scanner.Scanner { return security.NewTrailScanner(c) },
			`{"Trails":[],"NextToken":"next"}`, `{"Trails":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := mockClient(func(r *http.Request) (*http.Response, error) {
				body := tc.first
				_ = r.ParseForm()
				if r.Form.Get("Action") == "DescribeNetworkInterfaces" {
					body = `<DescribeNetworkInterfacesResponse><networkInterfaceSet/></DescribeNetworkInterfacesResponse>`
				} else {
					calls++
					if calls > 1 {
						body = tc.second
					}
					if calls > 2 {
						t.Errorf("requested unexpected page %d", calls)
					}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			cfg := aws.Config{Region: "eu-west-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: client, RetryMaxAttempts: 1}
			results, err := tc.newScanner(cfg).Scan(context.Background(), scanner.AuditRule{})
			if err != nil || calls != 2 {
				t.Fatalf("pages=%d err=%v", calls, err)
			}
			if (tc.name == "VPC" || tc.name == "SecurityGroups") && len(results) != 1 {
				t.Fatalf("lost second-page resource: %v", results)
			}
		})
	}
}

func TestCloudTrailKeepsHighestSeverity(t *testing.T) {
	client := mockClient(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch {
		case strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".ListTrails"):
			body = `{"Trails":[{"Name":"audit","TrailARN":"arn:aws:cloudtrail:eu-west-1:123456789012:trail/audit","HomeRegion":"eu-west-1"}]}`
		case strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".GetTrailStatus"):
			body = `{"IsLogging":true}`
		case strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".GetTrail"):
			body = `{"Trail":{"Name":"audit","LogFileValidationEnabled":false,"IsMultiRegionTrail":false}}`
		default:
			t.Errorf("unexpected operation: %s", r.Header.Get("X-Amz-Target"))
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	cfg := aws.Config{Region: "eu-west-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: client, RetryMaxAttempts: 1}
	results, err := security.NewTrailScanner(cfg).Scan(context.Background(), scanner.AuditRule{})
	if err != nil || len(results) != 1 || results[0].Risk != "HIGH" {
		t.Fatalf("earlier medium finding masked a high finding: %v, %v", results, err)
	}
}
