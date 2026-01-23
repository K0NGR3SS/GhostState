package data

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Scanner struct {
	Client *s3.Client
}

func NewS3Scanner(cfg aws.Config) *S3Scanner {
	return &S3Scanner{Client: s3.NewFromConfig(cfg)}
}

func (s *S3Scanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	out, err := s.Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	var results []scanner.Resource
	for _, b := range out.Buckets {
		res := scanner.Resource{
			ID:   aws.ToString(b.Name),
			Service: "S3",
			Type: "S3 Bucket",
			Status:  "Active",  
			Tags: map[string]string{},
			Risk: "SAFE",
		}

		pab, err := s.Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name})
		isPublic := false

		if err != nil {
			isPublic = true
			res.RiskInfo = "No Block Config Found"
		} else if pab.PublicAccessBlockConfiguration != nil {
			conf := pab.PublicAccessBlockConfiguration
			if (conf.BlockPublicAcls == nil || !*conf.BlockPublicAcls) ||
				(conf.BlockPublicPolicy == nil || !*conf.BlockPublicPolicy) ||
				(conf.IgnorePublicAcls == nil || !*conf.IgnorePublicAcls) ||
				(conf.RestrictPublicBuckets == nil || !*conf.RestrictPublicBuckets) {
				isPublic = true
				res.RiskInfo = "Public Access Allowed"
			}
		}

		if isPublic {
			res.Risk = "HIGH"
		}

		listOut, err := s.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  b.Name,
			MaxKeys: aws.Int32(1),
		})
		if err == nil && *listOut.KeyCount == 0 {
			res.IsGhost = true
			res.GhostInfo = "Empty Bucket"
		}

		if scanner.MatchesRule(res.Tags, rule) {
			results = append(results, res)
		}
	}

	return results, nil
}
