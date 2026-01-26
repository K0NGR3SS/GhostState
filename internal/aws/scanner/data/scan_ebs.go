package data

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type EBSScanner struct {
	Client *ec2.Client
}

func NewEBSScanner(cfg aws.Config) *EBSScanner {
	return &EBSScanner{Client: ec2.NewFromConfig(cfg)}
}

func (s *EBSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource

	p := ec2.NewDescribeVolumesPaginator(s.Client, &ec2.DescribeVolumesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, v := range out.Volumes {
			size := float64(0)
			if v.Size != nil {
				size = float64(*v.Size)
			}

			res := scanner.Resource{
				ID:      aws.ToString(v.VolumeId),
				Service: "EBS Volume",
				Type:    string(v.VolumeType),
				Size:    size,
				Status:  string(v.State),
				Tags:    map[string]string{},
				Risk:    "SAFE",
			}

			for _, t := range v.Tags {
				if t.Key != nil && t.Value != nil {
					res.Tags[*t.Key] = *t.Value
				}
			}

			var riskIssues []string

			// Check if volume is unattached (Ghost)
			if v.State == types.VolumeStateAvailable {
				res.IsGhost = true
				res.GhostInfo = "Unattached Volume"
			}

			// Check if volume is unencrypted (Security Risk)
			if v.Encrypted == nil || !*v.Encrypted {
				riskIssues = append(riskIssues, "Unencrypted")
				res.Risk = "HIGH"
			}

			// Check for old volume types (gp2 vs gp3 cost optimization)
			if v.VolumeType == types.VolumeTypeGp2 {
				riskIssues = append(riskIssues, "GP2 (consider upgrading to GP3 for cost savings)")
				if res.Risk == "SAFE" {
					res.Risk = "LOW"
				}
			}

			// Build risk info
			if len(riskIssues) > 0 {
				res.RiskInfo = riskIssues[0]
				for i := 1; i < len(riskIssues); i++ {
					res.RiskInfo += "; " + riskIssues[i]
				}
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}