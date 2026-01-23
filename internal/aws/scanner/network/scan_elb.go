package network

import (
	"context"

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
			res := scanner.Resource{
				ID:   aws.ToString(lb.LoadBalancerName),
				ARN:  aws.ToString(lb.LoadBalancerArn),
				Service: "ELB",
				Type: "Load Balancer",
				Status: string(lb.State.Code),
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			if lb.Scheme == "internet-facing" {
				res.Risk = "LOW"
				res.RiskInfo = "Internet Facing"
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
