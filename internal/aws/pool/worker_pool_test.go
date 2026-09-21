package pool

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func await(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker pool did not shut down")
	}
}

func TestErrorsDoNotBlockWorkers(t *testing.T) {
	wp := NewWorkerPool(context.Background(), 2)
	t.Cleanup(wp.Stop)
	want := errors.New("scan failed")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			wp.Submit(func(context.Context) error { return want })
		}
		wp.Wait()
	}()
	await(t, done)
	if got := wp.Errors(); len(got) != 100 || !errors.Is(got[0], want) {
		t.Fatalf("expected all 100 task errors, got %v", got)
	}
	wp.Wait()
	if wp.Submit(func(context.Context) error { return nil }) {
		t.Fatal("accepted work after Wait")
	}
}

func TestCancellationUnblocksFullQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wp := NewWorkerPool(ctx, 1)
	started := make(chan struct{})
	wp.Submit(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	await(t, started)
	var queuedRuns atomic.Int32
	queued := func(context.Context) error { queuedRuns.Add(1); return nil }
	wp.Submit(queued)
	wp.Submit(queued)
	done := make(chan struct{})
	go func() {
		wp.Submit(queued)
		wp.Wait()
		close(done)
	}()
	cancel()
	await(t, done)
	if queuedRuns.Load() != 0 {
		t.Fatal("ran queued tasks after cancellation")
	}
}

func TestConcurrentShutdownAndSubmit(t *testing.T) {
	wp := NewWorkerPool(context.Background(), 3)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wp.Start()
			wp.Submit(func(context.Context) error { return nil })
			wp.Stop()
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	await(t, done)
}

func TestInvalidWorkerCountStillProcessesTasks(t *testing.T) {
	wp := NewWorkerPool(context.Background(), 0)
	var ran atomic.Bool
	wp.Submit(func(context.Context) error { ran.Store(true); return nil })
	wp.Wait()
	if !ran.Load() {
		t.Fatal("task was never processed")
	}
}
