package network

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type ELBScanner struct {
	client *elasticloadbalancingv2.Client
}

func NewELBScanner(cfg aws.Config) *ELBScanner {
	return &ELBScanner{client: elasticloadbalancingv2.NewFromConfig(cfg)}
}

func (s *ELBScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, err
	}
	var res []scanner.Resource
	for _, lb := range out.LoadBalancers {
		res = append(res, scanner.Resource{
			ID:   *lb.LoadBalancerName,
			Type: "👻 [Load Balancer]",
			Tags: nil,
		})
	}
	return res, nil
}
