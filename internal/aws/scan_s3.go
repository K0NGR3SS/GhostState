package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	tea "github.com/charmbracelet/bubbletea"
)

func scanS3(cfg aws.Config, p *tea.Program, conf AuditConfig) {
	client := s3.NewFromConfig(cfg)

	resp, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		send(p, "S3: error listing buckets: "+err.Error())
		return
	}

	for _, b := range resp.Buckets {
		if b.Name == nil {
			continue
		}
		bucketName := *b.Name

		tagsResp, err := client.GetBucketTagging(context.TODO(), &s3.GetBucketTaggingInput{
			Bucket: &bucketName,
		})

		hasTag := false
		if err == nil {
			for _, t := range tagsResp.TagSet {
				if t.Key != nil && t.Value != nil &&
					*t.Key == conf.TargetKey && *t.Value == conf.TargetVal {
					hasTag = true
					break
				}
			}
		}

		if !hasTag {
			send(p, fmt.Sprintf("S3:  %s", bucketName))
		}
	}
}
