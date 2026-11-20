// Package events is a FIFO queue in which items of each droppable class have their own bound.
package events

import (
	"context"
	"errors"
	"sync"
)

// ErrDone means the done channel passed to Pop was closed.
var ErrDone = errors.New("koloswarm: queue done")

// Kept is the class of items that are never dropped.
const Kept = 0

type item[T any] struct {
	v     T
	class int
}

// Queue holds items in order; class i (from 1) holds at most budgets[i-1] items, and Kept items are always held.
type Queue[T any] struct {
	mu      sync.Mutex
	items   []item[T]
	queued  []int
	budgets []int
	ready   chan struct{}
}

// New returns a queue whose droppable class i (from 1) holds at most budgets[i-1] items.
func New[T any](budgets ...int) *Queue[T] {
	return &Queue[T]{queued: make([]int, len(budgets)+1), budgets: append([]int{0}, budgets...), ready: make(chan struct{}, 1)}
}

// Push appends v; it drops v and returns false if its class is full or unknown.
func (q *Queue[T]) Push(v T, class int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if class < 0 || class >= len(q.budgets) {
		return false
	}
	if class != Kept && q.queued[class] >= q.budgets[class] {
		return false
	}
	q.queued[class]++
	q.items = append(q.items, item[T]{v, class})
	q.signal()
	return true
}

// Remove deletes the first item for which match is true and reports whether there was one.
func (q *Queue[T]) Remove(match func(T) bool) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, it := range q.items {
		if match(it.v) {
			q.queued[it.class]--
			q.items = append(q.items[:i], q.items[i+1:]...)
			return true
		}
	}
	return false
}

// Len returns the number of queued items.
func (q *Queue[T]) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Pop waits for the first item; it returns ctx.Err() or ErrDone if ctx ends or done is closed first.
func (q *Queue[T]) Pop(ctx context.Context, done <-chan struct{}) (T, error) {
	var zero T
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			it := q.items[0]
			q.items[0] = item[T]{}
			q.items = q.items[1:]
			q.queued[it.class]--
			if len(q.items) > 0 {
				q.signal()
			}
			q.mu.Unlock()
			return it.v, nil
		}
		q.mu.Unlock()
		select {
		case <-q.ready:
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-done:
			return zero, ErrDone
		}
	}
}

// signal wakes one waiting Pop; call with mu held.
func (q *Queue[T]) signal() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}
