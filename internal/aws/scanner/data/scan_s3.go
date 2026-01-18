package data

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
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
		risk := "SAFE"
		info := ""

		pab, err := s.Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name})
		isPublic := false
		if err != nil {
			isPublic = true 
			info = "No Block Config Found"
		} else if pab.PublicAccessBlockConfiguration != nil {
			conf := pab.PublicAccessBlockConfiguration
			if (conf.BlockPublicAcls == nil || !*conf.BlockPublicAcls) || 
			   (conf.BlockPublicPolicy == nil || !*conf.BlockPublicPolicy) || 
			   (conf.IgnorePublicAcls == nil || !*conf.IgnorePublicAcls) || 
			   (conf.RestrictPublicBuckets == nil || !*conf.RestrictPublicBuckets) {
				isPublic = true
				info = "Public Access Allowed"
			}
		}

		if isPublic { risk = "HIGH" }

		// [FIX] Filter Modes
		if rule.ScanMode == "RISK" {
			if risk == "SAFE" { continue }
		}
		// S3 doesn't really have "Ghost" (unused) logic here yet, unless empty.
		// So Ghost mode just returns all buckets for now? Or skips SAFE ones?
		// Let's assume Ghost Mode users want to see all buckets to find unused ones manually.

		tags := map[string]string{} 

		if scanner.MatchesRule(tags, rule) {
			// [FIX] Clean Type String
			results = append(results, scanner.Resource{
				ID:   *b.Name,
				Type: "S3 Bucket",
				Tags: tags,
				Risk: risk,
				Info: info,
			})
		}
	}
	return results, nil
}