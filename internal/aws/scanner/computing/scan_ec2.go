package computing

import (
	"context"
	"fmt"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type EC2Scanner struct {
	Client *ec2.Client
}

func NewEC2Scanner(cfg aws.Config) *EC2Scanner {
	return &EC2Scanner{Client: ec2.NewFromConfig(cfg)}
}

func (s *EC2Scanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := ec2.NewDescribeInstancesPaginator(s.Client, &ec2.DescribeInstancesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, r := range out.Reservations {
			for _, inst := range r.Instances {
				stateName := "unknown"
				if inst.State != nil {
					stateName = string(inst.State.Name)
				}

				res := scanner.Resource{
					ID:      aws.ToString(inst.InstanceId),
					Service: "EC2",
					Type:    string(inst.InstanceType), // Specific Type (e.g. t3.micro) for Pricing
					Status:  stateName,
					Tags:    map[string]string{},
					Risk:    "SAFE",
				}

				for _, t := range inst.Tags {
					if t.Key != nil && t.Value != nil {
						res.Tags[*t.Key] = *t.Value
					}
				}

				if inst.State != nil && inst.State.Name == types.InstanceStateNameStopped {
					res.IsGhost = true
					res.GhostInfo = fmt.Sprintf("Stopped (%s)", string(inst.InstanceType))
				}

				if inst.State != nil && inst.State.Name == types.InstanceStateNameRunning && inst.PublicIpAddress != nil {
					res.Risk = "HIGH"
					res.RiskInfo = fmt.Sprintf("Public IP: %s", *inst.PublicIpAddress)
				}
				if scanner.MatchesRule(res.Tags, rule) {
					results = append(results, res)
				}
			}
		}
	}

	return results, nil
}