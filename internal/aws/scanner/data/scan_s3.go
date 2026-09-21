package data

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type S3Scanner struct {
	Client *s3.Client
}

func NewS3Scanner(cfg aws.Config) *S3Scanner {
	return &S3Scanner{Client: s3.NewFromConfig(cfg)}
}

func apiErrorCode(err error, code string) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == code
}

func (s *S3Scanner) Scan(ctx context.Context, rule scanner.AuditRule) ([]scanner.Resource, error) {
	var results []scanner.Resource
	var checkErrors []error
	pages := s3.NewListBucketsPaginator(s.Client, &s3.ListBucketsInput{MaxBuckets: aws.Int32(1000)})
	for pages.HasMorePages() {
		out, err := pages.NextPage(ctx)
		if err != nil {
			return results, errors.Join(append(checkErrors, err)...)
		}
		for _, bucket := range out.Buckets {
			if err := ctx.Err(); err != nil {
				return results, errors.Join(append(checkErrors, err)...)
			}
			client := s.Client
			region := aws.ToString(bucket.BucketRegion)
			if region != "" && region != client.Options().Region {
				options := client.Options()
				options.Region = region
				client = s3.New(options)
			}
			res := scanner.Resource{
				ID: aws.ToString(bucket.Name), Service: "S3", Type: "S3 Bucket",
				Region: region, Status: "Active", Tags: map[string]string{}, Risk: "SAFE",
			}
			var riskIssues, unavailable []string
			recordError := func(check string, err error) {
				checkErrors = append(checkErrors, fmt.Errorf("bucket %s: %s: %w", res.ID, check, err))
				unavailable = append(unavailable, check)
			}
			tags, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: bucket.Name})
			if err == nil {
				for _, tag := range tags.TagSet {
					res.Tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
				}
			} else if !apiErrorCode(err, "NoSuchTagSet") {
				recordError("tags", err)
			}

			pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: bucket.Name})
			switch {
			case apiErrorCode(err, "NoSuchPublicAccessBlockConfiguration"):
				res.Risk = "HIGH"
				riskIssues = append(riskIssues, "Bucket Public Access Block Missing")
			case err != nil:
				recordError("public access block", err)
			case pab.PublicAccessBlockConfiguration == nil:
				recordError("public access block", errors.New("empty configuration response"))
			default:
				conf := pab.PublicAccessBlockConfiguration
				if !aws.ToBool(conf.BlockPublicAcls) || !aws.ToBool(conf.BlockPublicPolicy) ||
					!aws.ToBool(conf.IgnorePublicAcls) || !aws.ToBool(conf.RestrictPublicBuckets) {
					res.Risk = "HIGH"
					riskIssues = append(riskIssues, "Bucket Public Access Block Incomplete")
				}
			}

			versioning, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket.Name})
			if err != nil {
				recordError("versioning", err)
			} else if versioning.Status != types.BucketVersioningStatusEnabled {
				riskIssues = append(riskIssues, "Versioning Disabled")
				if res.Risk == "SAFE" {
					res.Risk = "MEDIUM"
				}
			}

			encryption, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket.Name})
			if err != nil {
				// AccessDenied and missing configuration do not prove objects are unencrypted.
				recordError("encryption", err)
			} else if encryption.ServerSideEncryptionConfiguration == nil {
				recordError("encryption", errors.New("empty configuration response"))
			}

			logging, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: bucket.Name})
			if err != nil {
				recordError("logging", err)
			} else if logging.LoggingEnabled == nil {
				riskIssues = append(riskIssues, "Logging Disabled")
				if res.Risk == "SAFE" {
					res.Risk = "LOW"
				}
			}

			objects, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: bucket.Name, MaxKeys: aws.Int32(1)})
			if err != nil {
				recordError("objects", err)
			} else if objects.KeyCount != nil && *objects.KeyCount == 0 {
				res.IsGhost = true
				res.GhostInfo = "Empty Bucket"
			}

			res.RiskInfo = strings.Join(riskIssues, "; ")
			if len(unavailable) > 0 {
				res.Info = "Checks unavailable: " + strings.Join(unavailable, ", ")
				if res.Risk == "SAFE" {
					res.Risk = "UNKNOWN"
				}
			}
			if scanner.MatchesRule(res.Tags, rule) {
				results = append(results, res)
			}
		}
	}
	return results, errors.Join(checkErrors...)
}
