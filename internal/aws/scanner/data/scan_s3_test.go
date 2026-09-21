package data

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type s3HTTPClient func(*http.Request) (*http.Response, error)

func (f s3HTTPClient) Do(r *http.Request) (*http.Response, error) { return f(r) }

func s3Response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/xml"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestS3PaginatesAndUsesBucketRegion(t *testing.T) {
	pages, checks := 0, 0
	client := s3HTTPClient(func(r *http.Request) (*http.Response, error) {
		q := r.URL.Query()
		if q.Has("max-buckets") {
			pages++
			if pages == 1 {
				return s3Response(200, `<ListAllMyBucketsResult><Buckets/><ContinuationToken>next</ContinuationToken></ListAllMyBucketsResult>`), nil
			}
			if q.Get("continuation-token") != "next" {
				t.Errorf("missing continuation token: %s", r.URL)
			}
			return s3Response(200, `<ListAllMyBucketsResult><Buckets><Bucket><Name>test-bucket</Name><BucketRegion>ap-south-1</BucketRegion></Bucket></Buckets></ListAllMyBucketsResult>`), nil
		}
		checks++
		if !strings.Contains(r.URL.Host, "ap-south-1") {
			t.Errorf("bucket check used wrong region: %s", r.URL.Host)
		}
		switch {
		case q.Has("tagging"):
			return s3Response(200, `<Tagging><TagSet><Tag><Key>Owner</Key><Value>team</Value></Tag></TagSet></Tagging>`), nil
		case q.Has("publicAccessBlock"):
			return s3Response(200, `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`), nil
		case q.Has("versioning"):
			return s3Response(200, `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`), nil
		case q.Has("encryption"):
			return s3Response(200, `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`), nil
		case q.Has("logging"):
			return s3Response(200, `<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket></LoggingEnabled></BucketLoggingStatus>`), nil
		case q.Has("list-type"):
			return s3Response(200, `<ListBucketResult><KeyCount>1</KeyCount></ListBucketResult>`), nil
		default:
			t.Errorf("unexpected request: %s", r.URL)
			return s3Response(500, ``), nil
		}
	})
	cfg := aws.Config{Region: "eu-west-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: client, RetryMaxAttempts: 1}
	results, err := NewS3Scanner(cfg).Scan(context.Background(), scanner.AuditRule{TargetKey: "Owner", TargetVal: "team"})
	if err != nil || len(results) != 1 || pages != 2 || checks != 6 {
		t.Fatalf("results=%v pages=%d checks=%d err=%v", results, pages, checks, err)
	}
	if r := results[0]; r.Region != "ap-south-1" || r.Risk != "SAFE" || r.IsGhost {
		t.Fatalf("incorrect bucket evaluation: %+v", r)
	}
}

func TestS3DeniedChecksAreUnknownNotFalseFindings(t *testing.T) {
	client := s3HTTPClient(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Has("max-buckets") {
			return s3Response(200, `<ListAllMyBucketsResult><Buckets><Bucket><Name>test-bucket</Name><BucketRegion>eu-west-1</BucketRegion></Bucket></Buckets></ListAllMyBucketsResult>`), nil
		}
		return s3Response(403, `<Error><Code>AccessDenied</Code><Message>denied</Message></Error>`), nil
	})
	cfg := aws.Config{Region: "eu-west-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: client, RetryMaxAttempts: 1}
	results, err := NewS3Scanner(cfg).Scan(context.Background(), scanner.AuditRule{})
	if err == nil || len(results) != 1 {
		t.Fatalf("inventory/partial error missing: %v, %v", results, err)
	}
	if r := results[0]; r.Risk != "UNKNOWN" || r.RiskInfo != "" || r.IsGhost || r.Info == "" {
		t.Fatalf("access errors turned into false findings: %+v", r)
	}
}
