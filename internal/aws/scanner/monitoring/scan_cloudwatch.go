package monitoring

import (
	"context"
	"fmt"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type CloudWatchScanner struct {
	Client *cloudwatch.Client
}

func NewCloudWatchScanner(cfg aws.Config) *CloudWatchScanner {
	return &CloudWatchScanner{Client: cloudwatch.NewFromConfig(cfg)}
}

func (s *CloudWatchScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := cloudwatch.NewDescribeAlarmsPaginator(s.Client, &cloudwatch.DescribeAlarmsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, a := range out.MetricAlarms {
			res := scanner.Resource{
				ID:   aws.ToString(a.AlarmName),
				ARN:  aws.ToString(a.AlarmArn),
				Type: "CloudWatch Alarm",
				Tags: map[string]string{},
				Risk: "SAFE",
			}

			if a.StateValue == types.StateValueInsufficientData {
				res.IsGhost = true
				res.GhostInfo = "Insufficient Data (Unused?)"
			}

			if a.StateValue == types.StateValueAlarm {
				res.Risk = "HIGH"
				res.RiskInfo = fmt.Sprintf("In ALARM State: %s", aws.ToString(a.StateReason))
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
