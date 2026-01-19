package security

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

type TrailScanner struct {
	client *cloudtrail.Client
}

func NewTrailScanner(cfg aws.Config) *TrailScanner {
	return &TrailScanner{client: cloudtrail.NewFromConfig(cfg)}
}

func (s *TrailScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	listOut, err := s.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil {
		return nil, err
	}

	for _, trail := range listOut.Trails {
		res := scanner.Resource{
			ID:   aws.ToString(trail.Name),
			ARN:  aws.ToString(trail.TrailARN),
			Type: "CloudTrail",
			Tags: map[string]string{"Region": aws.ToString(trail.HomeRegion)},
			Risk: "SAFE",
		}

		status, err := s.client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})

		if err == nil {
			if !aws.ToBool(status.IsLogging) {
				res.Risk = "CRITICAL"
				res.RiskInfo = "Logging is STOPPED"
			} else {
				desc, err := s.client.GetTrail(ctx, &cloudtrail.GetTrailInput{
					Name: trail.TrailARN,
				})
				if err == nil && desc.Trail != nil {
					if !aws.ToBool(desc.Trail.LogFileValidationEnabled) {
						res.Risk = "MEDIUM"
						res.RiskInfo = "Log Validation Disabled"
					}
				}
			}
		}

		if scanner.MatchesRule(res.Tags, rule) {
			results = append(results, res)
		}
	}

	return results, nil
}
