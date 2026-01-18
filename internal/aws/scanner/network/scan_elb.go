package network

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type ELBScanner struct {
	Client *elasticloadbalancingv2.Client
}

func NewELBScanner(cfg aws.Config) *ELBScanner {
	return &ELBScanner{Client: elasticloadbalancingv2.NewFromConfig(cfg)}
}

func (s *ELBScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, lb := range out.LoadBalancers {
		risk := "SAFE"
		info := ""

		// Check if Internet Facing
		if lb.Scheme == types.LoadBalancerSchemeEnumInternetFacing {
			risk = "LOW" 
			info = "Internet Facing"
		}

		if rule.ScanMode == "RISK" {
			if risk == "SAFE" || risk == "LOW" { continue }
		}
		tags := map[string]string{}

		if scanner.MatchesRule(tags, rule) {
			results = append(results, scanner.Resource{
				ID:   *lb.LoadBalancerName,
				Type: "Load Balancer",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}
