package data

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/K0NGR3SS/GhostState/internal/aws/clients"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type S3Scanner struct {
	client *s3.Client
}

func NewS3Scanner(cfg aws.Config) *S3Scanner {
	return &S3Scanner{client: clients.NewS3(cfg)}
}

func (s *S3Scanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var resources []scanner.Resource
	
	resp, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	for _, b := range resp.Buckets {
		if b.Name == nil { continue }
		name := *b.Name

		tagsResp, err := s.client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &name})
		tagMap := make(map[string]string)

		if err == nil {
			for _, t := range tagsResp.TagSet {
				if t.Key != nil && t.Value != nil { tagMap[*t.Key] = *t.Value }
			}
		}

		if !scanner.IsCompliant(tagMap, rule) {
			resources = append(resources, scanner.Resource{
				Type: "S3 Bucket",
				ID:   name,
				ARN:  fmt.Sprintf("arn:aws:s3:::%s", name),
			})
		}
	}
	return resources, nil
}
