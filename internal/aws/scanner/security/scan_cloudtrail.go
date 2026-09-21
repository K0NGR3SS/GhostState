package security

import (
	"context"
	"strings"

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

	pages := cloudtrail.NewListTrailsPaginator(s.client, &cloudtrail.ListTrailsInput{})
	for pages.HasMorePages() {
		listOut, err := pages.NextPage(ctx)
		if err != nil {
			return results, err
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

			var riskIssues []string
			if err == nil {
				if !aws.ToBool(status.IsLogging) {
					res.Risk = "CRITICAL"
					riskIssues = append(riskIssues, "Logging is STOPPED")
				} else {
					desc, err := s.client.GetTrail(ctx, &cloudtrail.GetTrailInput{
						Name: trail.TrailARN,
					})
					if err == nil && desc.Trail != nil {
						if !aws.ToBool(desc.Trail.LogFileValidationEnabled) {
							res.Risk = "MEDIUM"
							riskIssues = append(riskIssues, "Log Validation Disabled")
						}
						if !aws.ToBool(desc.Trail.IsMultiRegionTrail) {
							if res.Risk != "CRITICAL" {
								res.Risk = "HIGH"
							}
							riskIssues = append(riskIssues, "Not Multi-Region")
						}
						if aws.ToString(desc.Trail.KmsKeyId) == "" {
							if res.Risk == "SAFE" {
								res.Risk = "MEDIUM"
							}
							riskIssues = append(riskIssues, "KMS Encryption Not Configured")
						}
						if aws.ToString(desc.Trail.CloudWatchLogsLogGroupArn) == "" {
							if res.Risk == "SAFE" {
								res.Risk = "MEDIUM"
							}
							riskIssues = append(riskIssues, "CloudWatch Logs Integration Missing")
						}
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
