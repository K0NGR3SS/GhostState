package network

import (
	"context"
	"strings"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

type ELBScanner struct {
	Client *elasticloadbalancingv2.Client
}

func NewELBScanner(cfg aws.Config) *ELBScanner {
	return &ELBScanner{Client: elasticloadbalancingv2.NewFromConfig(cfg)}
}

func (s *ELBScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(s.Client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, lb := range out.LoadBalancers {
			status := "unknown"
			if lb.State != nil {
				status = string(lb.State.Code)
			}

			res := scanner.Resource{
				ID:      aws.ToString(lb.LoadBalancerName),
				ARN:     aws.ToString(lb.LoadBalancerArn),
				Service: "ELB",
				Type:    "Load Balancer",
				Status:  status,
				Tags:    map[string]string{},
				Risk:    "SAFE",
			}

			if lb.LoadBalancerArn != nil {
				tagOut, err := s.Client.DescribeTags(ctx, &elasticloadbalancingv2.DescribeTagsInput{
					ResourceArns: []string{*lb.LoadBalancerArn},
				})
				if err == nil {
					for _, tagDesc := range tagOut.TagDescriptions {
						for _, tag := range tagDesc.Tags {
							if tag.Key != nil && tag.Value != nil {
								res.Tags[*tag.Key] = *tag.Value
							}
						}
					}
				}
			}

			var riskIssues []string
			if lb.Scheme == "internet-facing" {
				res.Risk = "LOW"
				riskIssues = append(riskIssues, "Internet Facing")
			}

			if lb.LoadBalancerArn != nil {
				attrOut, err := s.Client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
					LoadBalancerArn: lb.LoadBalancerArn,
				})
				if err == nil {
					accessLoggingEnabled := false
					for _, attr := range attrOut.Attributes {
						if aws.ToString(attr.Key) == "access_logs.s3.enabled" && aws.ToString(attr.Value) == "true" {
							accessLoggingEnabled = true
							break
						}
					}
					if !accessLoggingEnabled {
						if res.Risk == "SAFE" {
							res.Risk = "LOW"
						}
						riskIssues = append(riskIssues, "Access Logging Disabled")
					}
				}

				listenerOut, err := s.Client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
					LoadBalancerArn: lb.LoadBalancerArn,
				})
				if err == nil && len(listenerOut.Listeners) > 0 {
					hasSecureListener := false
					for _, listener := range listenerOut.Listeners {
						protocol := strings.ToUpper(string(listener.Protocol))
						if protocol == "HTTPS" || protocol == "TLS" {
							hasSecureListener = true
							break
						}
					}
					if lb.Scheme == "internet-facing" && !hasSecureListener {
						if res.Risk == "SAFE" || res.Risk == "LOW" {
							res.Risk = "MEDIUM"
						}
						riskIssues = append(riskIssues, "No HTTPS/TLS Listener")
					}
				}
			}

			if len(riskIssues) > 0 {
				res.RiskInfo = strings.Join(riskIssues, "; ")
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
