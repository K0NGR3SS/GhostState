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

	pages := route53.NewListHostedZonesPaginator(s.client, &route53.ListHostedZonesInput{})
	for pages.HasMorePages() {
		listOut, err := pages.NextPage(ctx)
		if err != nil {
			return results, err
		}
		for _, zone := range listOut.HostedZones {
			res := scanner.Resource{
				ID:      aws.ToString(zone.Id),
				Service: "Route53",
				Type:    "Route53 Zone",
				Status:  "Active",
				Tags:    map[string]string{"Name": aws.ToString(zone.Name)},
				Risk:    "SAFE",
			}

			recs, err := s.client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
				HostedZoneId: zone.Id,
				MaxItems:     aws.Int32(5),
			})

			if err == nil && recs != nil {
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

	}
	return results, nil
}
