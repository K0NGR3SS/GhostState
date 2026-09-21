package pool

import (
	"context"
	"sync"
)

// Task represents a unit of work. Tasks must honor context cancellation.
type Task func(ctx context.Context) error

// WorkerPool limits concurrent work and collects errors without blocking workers.
// Start, Submit, Wait, and Stop may be called concurrently.
type WorkerPool struct {
	maxWorkers int
	tasks      chan Task
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	startOnce  sync.Once
	waitOnce   sync.Once
	mu         sync.RWMutex
	closed     bool
	errMu      sync.Mutex
	errors     []error
}

func NewWorkerPool(ctx context.Context, maxWorkers int) *WorkerPool {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	ctx, cancel := context.WithCancel(ctx)
	return &WorkerPool{
		maxWorkers: maxWorkers,
		tasks:      make(chan Task, maxWorkers*2),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start initializes the workers once. Submit and Wait also start them if needed.
func (wp *WorkerPool) Start() {
	wp.startOnce.Do(func() {
		wp.wg.Add(wp.maxWorkers)
		for i := 0; i < wp.maxWorkers; i++ {
			go wp.worker()
		}
	})
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case task, ok := <-wp.tasks:
			if !ok || wp.ctx.Err() != nil {
				return
			}
			if err := task(wp.ctx); err != nil {
				wp.errMu.Lock()
				wp.errors = append(wp.errors, err)
				wp.errMu.Unlock()
			}
		}
	}
}

// Submit reports whether a task was accepted. Submissions after shutdown are rejected.
func (wp *WorkerPool) Submit(task Task) bool {
	if task == nil {
		return false
	}
	wp.Start()
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	if wp.closed || wp.ctx.Err() != nil {
		return false
	}
	select {
	case <-wp.ctx.Done():
		return false
	case wp.tasks <- task:
		return true
	}
}

// Wait stops accepting tasks and waits for accepted work to finish.
func (wp *WorkerPool) Wait() {
	wp.Start()
	wp.waitOnce.Do(func() {
		wp.mu.Lock()
		wp.closed = true
		close(wp.tasks)
		wp.mu.Unlock()
		wp.wg.Wait()
		wp.cancel()
	})
}

// Stop cancels running tasks and discards queued work before waiting for shutdown.
func (wp *WorkerPool) Stop() {
	wp.cancel()
	wp.Wait()
}

// Errors returns a snapshot; call after Wait to obtain all task errors.
func (wp *WorkerPool) Errors() []error {
	wp.errMu.Lock()
	defer wp.errMu.Unlock()
	return append([]error(nil), wp.errors...)
}
