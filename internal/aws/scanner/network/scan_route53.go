package network

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

type Route53Scanner struct {
	client *route53.Client
}

func NewRoute53Scanner(cfg aws.Config) *Route53Scanner {
	return &Route53Scanner{client: route53.NewFromConfig(cfg)}
}

func (s *Route53Scanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	listOut, err := s.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
	if err != nil {
		return nil, err
	}

	for _, zone := range listOut.HostedZones {
		res := scanner.Resource{
			ID:   aws.ToString(zone.Id),
			Type: "Route53 Zone",
			Tags: map[string]string{"Name": aws.ToString(zone.Name)},
			Risk: "SAFE",
		}

		recs, err := s.client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
			HostedZoneId: zone.Id,
			MaxItems:     aws.Int32(5),
		})
		
		if err == nil {
			if len(recs.ResourceRecordSets) <= 2 {
				res.IsGhost = true
				res.GhostInfo = "Empty Hosted Zone (only SOA/NS records)"
			}
		}

		if zone.Config != nil && zone.Config.PrivateZone {
			res.Tags["Visibility"] = "Private"
		} else {
			res.Tags["Visibility"] = "Public"
		}

		if scanner.MatchesRule(res.Tags, rule) {
			results = append(results, res)
		}
	}

	return results, nil
}
