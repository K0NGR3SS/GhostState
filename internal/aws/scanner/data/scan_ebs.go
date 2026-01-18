package data

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type EBSScanner struct {
	Client *ec2.Client
}

func NewEBSScanner(cfg aws.Config) *EBSScanner {
    return &EBSScanner{Client: ec2.NewFromConfig(cfg)}
}

func (s *EBSScanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	input := &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("status"),
				Values: []string{"available"},
			},
		},
	}

	out, err := s.Client.DescribeVolumes(ctx, input)
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, v := range out.Volumes {
		size := int32(0)
		if v.Size != nil {
			size = *v.Size
		}
        id := "unknown"
        if v.VolumeId != nil { id = *v.VolumeId }

		results = append(results, scanner.Resource{
			ID:   fmt.Sprintf("%s (%d GB)", id, size),
			Type: "👻 [EBS Volume (Unattached)]",
			Tags: convertTagsEC2(v.Tags),
		})
	}
	return results, nil
}

func convertTagsEC2(tags []types.Tag) map[string]string {
	m := make(map[string]string)
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			m[*t.Key] = *t.Value
		}
	}
	return m
}
