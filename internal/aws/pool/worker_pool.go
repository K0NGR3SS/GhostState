package pool

import (
	"context"
	"sync"
)

// Task represents a unit of work
type Task func(ctx context.Context) error

// WorkerPool manages a pool of workers for concurrent task execution
type WorkerPool struct {
	maxWorkers int
	tasks      chan Task
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	errors     chan error
}

// NewWorkerPool creates a new worker pool with specified max workers
func NewWorkerPool(maxWorkers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		maxWorkers: maxWorkers,
		tasks:      make(chan Task, maxWorkers*2),
		ctx:        ctx,
		cancel:     cancel,
		errors:     make(chan error, maxWorkers),
	}
}

// Start initializes the worker pool
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.maxWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

// worker processes tasks from the task channel
func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case task, ok := <-wp.tasks:
			if !ok {
				return
			}
			if err := task(wp.ctx); err != nil {
				select {
				case wp.errors <- err:
				}
			}
		}
	}
}

// Submit adds a task to the worker pool
func (wp *WorkerPool) Submit(task Task) {
	select {
	case <-wp.ctx.Done():
		return
	case wp.tasks <- task:
	}
}

// Wait closes the task channel and waits for all workers to finish
func (wp *WorkerPool) Wait() {
	close(wp.tasks)
	wp.wg.Wait()
	close(wp.errors)
}

// Stop cancels the context and stops all workers
func (wp *WorkerPool) Stop() {
	wp.cancel()
	wp.Wait()
}

// Errors returns a channel to receive errors from workers
func (wp *WorkerPool) Errors() <-chan error {
	return wp.errors
}