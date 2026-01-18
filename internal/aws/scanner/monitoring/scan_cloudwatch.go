package monitoring

import (
	"context"
	"fmt"
    "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
    "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type CloudWatchScanner struct {
	Client *cloudwatch.Client
}

func NewCloudWatchScanner(cfg aws.Config) *CloudWatchScanner {
    return &CloudWatchScanner{Client: cloudwatch.NewFromConfig(cfg)}
}

func (s *CloudWatchScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
    input := &cloudwatch.DescribeAlarmsInput{
        StateValue: types.StateValueInsufficientData, 
    }

	out, err := s.Client.DescribeAlarms(ctx, input)
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, a := range out.MetricAlarms {
		results = append(results, scanner.Resource{
			ID:   fmt.Sprintf("%s (State: %s)", *a.AlarmName, a.StateValue),
			Type: "👻 [CloudWatch Alarm]",
		})
	}
	return results, nil
}
