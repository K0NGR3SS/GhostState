package data

import (
	"context"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
			ID:      aws.ToString(b.Name),
			Service: "S3",
			Type:    "S3 Bucket",
			Status:  "Active",
			Tags:    map[string]string{},
			Risk:    "SAFE",
		}

		bucketName := b.Name
		var riskIssues []string

		// Check public access block
		pab, err := s.Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: bucketName})
		isPublic := false

		if err != nil {
			isPublic = true
			riskIssues = append(riskIssues, "No Public Access Block")
		} else if pab.PublicAccessBlockConfiguration != nil {
			conf := pab.PublicAccessBlockConfiguration
			if (conf.BlockPublicAcls == nil || !*conf.BlockPublicAcls) ||
				(conf.BlockPublicPolicy == nil || !*conf.BlockPublicPolicy) ||
				(conf.IgnorePublicAcls == nil || !*conf.IgnorePublicAcls) ||
				(conf.RestrictPublicBuckets == nil || !*conf.RestrictPublicBuckets) {
				isPublic = true
				riskIssues = append(riskIssues, "Public Access Allowed")
			}
		}

		// Check versioning
		versioningOut, err := s.Client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: bucketName,
		})
		if err == nil {
			if versioningOut.Status != types.BucketVersioningStatusEnabled {
				riskIssues = append(riskIssues, "Versioning Disabled")
				if res.Risk == "SAFE" {
					res.Risk = "MEDIUM"
				}
			}
		}

		// Check encryption
		encryptionOut, err := s.Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucketName,
		})
		if err != nil || encryptionOut.ServerSideEncryptionConfiguration == nil {
			riskIssues = append(riskIssues, "Encryption Disabled")
			if res.Risk == "SAFE" || res.Risk == "MEDIUM" {
				res.Risk = "MEDIUM"
			}
		}

		// Check for logging
		loggingOut, err := s.Client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: bucketName,
		})
		if err == nil && loggingOut.LoggingEnabled == nil {
			riskIssues = append(riskIssues, "Logging Disabled")
		}

		// Public access is highest priority
		if isPublic {
			res.Risk = "HIGH"
		}

		// Build risk info string
		if len(riskIssues) > 0 {
			res.RiskInfo = riskIssues[0]
			if len(riskIssues) > 1 {
				for i := 1; i < len(riskIssues); i++ {
					res.RiskInfo += "; " + riskIssues[i]
				}
			}
		}

		// Check if bucket is empty
		listOut, err := s.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  bucketName,
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