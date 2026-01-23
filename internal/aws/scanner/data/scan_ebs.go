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

			if v.State == types.VolumeStateAvailable {
				res.IsGhost = true
				res.GhostInfo = "Unattached Volume"
			}

			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}

	return results, nil
}
