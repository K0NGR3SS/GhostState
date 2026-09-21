package aws

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/K0NGR3SS/GhostState/internal/aws/cache"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type testHTTPClient func(*http.Request) (*http.Response, error)

func (f testHTTPClient) Do(r *http.Request) (*http.Response, error) { return f(r) }

func testProvider(client testHTTPClient) *Provider {
	return &Provider{
		cfg:    aws.Config{Region: "eu-west-1", Credentials: aws.AnonymousCredentials{}, HTTPClient: client, RetryMaxAttempts: 1},
		region: "eu-west-1", accountID: "123456789012", tagCache: cache.NewTagCache(time.Minute),
	}
}

func xmlResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestScanRetainsEarlierPagesAndStreamsPartialResults(t *testing.T) {
	var requests atomic.Int32
	p := testProvider(func(r *http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			return xmlResponse(200, `<DescribeVolumesResponse><volumeSet><item><volumeId>vol-first</volumeId><size>10</size><status>available</status><volumeType>gp3</volumeType><encrypted>true</encrypted></item></volumeSet><nextToken>next</nextToken></DescribeVolumesResponse>`), nil
		}
		return xmlResponse(403, `<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>denied</Message></Error></Errors></Response>`), nil
	})
	var streamed []scanner.Resource
	var failures []scanner.ScanError
	var scope []string
	results, scanErrors, err := p.ScanAllWithProgress(context.Background(), scanner.AuditConfig{ScanEBS: true}, ScanProgress{
		Resource: func(r scanner.Resource) { streamed = append(streamed, r) },
		Error:    func(e scanner.ScanError) { failures = append(failures, e) },
		Regions:  func(regions []string) { scope = regions },
	})
	if err != nil || len(results) != 1 || len(scanErrors) != 1 {
		t.Fatalf("results=%v errors=%v fatal=%v", results, scanErrors, err)
	}
	if !reflect.DeepEqual(streamed, results) || !reflect.DeepEqual(failures, scanErrors) {
		t.Fatal("streamed and final results disagree")
	}
	if results[0].AccountID != p.accountID || results[0].Region != p.region || results[0].SavingsEstimate <= 0 {
		t.Fatalf("partial result lost enrichment: %+v", results[0])
	}
	if !reflect.DeepEqual(scope, []string{p.region}) {
		t.Fatalf("incorrect resolved scope: %v", scope)
	}
}

func TestScanCancellationReachesAWSRequest(t *testing.T) {
	started := make(chan struct{})
	p := testProvider(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := p.ScanAll(ctx, scanner.AuditConfig{ScanEBS: true})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("AWS request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scan ignored caller cancellation")
	}
}

func TestResolveRegionsRejectsEmptyCustomScope(t *testing.T) {
	p := testProvider(nil)
	_, err := p.resolveRegions(context.Background(), scanner.AuditConfig{RegionMode: scanner.RegionModeCustom, Regions: []string{" "}})
	if err == nil {
		t.Fatal("empty custom scope silently fell back to the current region")
	}
	regions, err := p.resolveRegions(context.Background(), scanner.AuditConfig{
		RegionMode: scanner.RegionModeCustom, Regions: []string{" eu-west-1 ", "eu-west-1", "us-east-1"},
	})
	if err != nil || !reflect.DeepEqual(regions, []string{"eu-west-1", "us-east-1"}) {
		t.Fatalf("regions=%v err=%v", regions, err)
	}
}

func TestGlobalServicesOnlyScannedOnce(t *testing.T) {
	var calls atomic.Int32
	p := testProvider(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return xmlResponse(200, `<ListDistributionsResponse><DistributionList><IsTruncated>false</IsTruncated><Quantity>0</Quantity></DistributionList></ListDistributionsResponse>`), nil
	})
	_, failures, err := p.ScanAll(context.Background(), scanner.AuditConfig{
		ScanCloudfront: true, Regions: []string{"eu-west-1", "us-east-1", "eu-west-1"},
	})
	if err != nil || len(failures) != 0 || calls.Load() != 1 {
		t.Fatalf("calls=%d failures=%v err=%v", calls.Load(), failures, err)
	}
}

func TestRegionConcurrencyIsBounded(t *testing.T) {
	started := make(chan struct{}, 10)
	release := make(chan struct{})
	var active, peak atomic.Int32
	p := testProvider(func(r *http.Request) (*http.Response, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return xmlResponse(200, `<DescribeVolumesResponse><volumeSet/></DescribeVolumesResponse>`), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := p.ScanAll(ctx, scanner.AuditConfig{ScanEBS: true, Regions: []string{
			"eu-west-1", "eu-west-2", "eu-west-3", "us-east-1", "us-east-2", "us-west-1", "us-west-2",
		}})
		done <- err
	}()
	for i := 0; i < 3; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("expected three concurrent regions")
		}
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scan did not finish")
	}
	if peak.Load() != 3 {
		t.Fatalf("peak concurrent regions = %d", peak.Load())
	}
}
