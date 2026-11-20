package events

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestOrderAndDrops(t *testing.T) {
	q := New[int](2)
	q.Push(1, 1)
	q.Push(2, Kept)
	q.Push(3, 1)
	if q.Push(4, 1) {
		t.Fatal("third droppable item kept with a bound of 2")
	}
	q.Push(5, Kept)
	if q.Len() != 4 {
		t.Fatalf("Len = %d, want 4", q.Len())
	}
	for _, want := range []int{1, 2, 3, 5} {
		got, err := q.Pop(context.Background(), nil)
		if err != nil || got != want {
			t.Fatalf("Pop = %d, %v; want %d", got, err, want)
		}
	}
	if !q.Push(6, 1) {
		t.Fatal("droppable item refused after the queue drained")
	}
}

func TestKeptItemsUnbounded(t *testing.T) {
	q := New[int](1)
	for i := range 100 {
		if !q.Push(i, Kept) {
			t.Fatalf("kept item %d refused", i)
		}
	}
	if q.Len() != 100 {
		t.Fatalf("Len = %d", q.Len())
	}
}

func TestRemove(t *testing.T) {
	q := New[int](4)
	q.Push(1, Kept)
	q.Push(2, 1)
	q.Push(3, Kept)
	if !q.Remove(func(v int) bool { return v == 2 }) {
		t.Fatal("Remove found nothing")
	}
	if q.Remove(func(v int) bool { return v == 9 }) {
		t.Fatal("Remove matched a missing item")
	}
	q.Push(4, 1)
	q.Push(5, 1)
	q.Push(6, 1)
	q.Push(7, 1)
	if q.Push(8, 1) {
		t.Fatal("removed droppable item still counted")
	}
}

func TestPopWaits(t *testing.T) {
	q := New[int](4)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		q.Push(7, Kept)
	}()
	got, err := q.Pop(context.Background(), nil)
	wg.Wait()
	if err != nil || got != 7 {
		t.Fatalf("Pop = %d, %v", got, err)
	}
}

func TestPopCanceled(t *testing.T) {
	q := New[int](4)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := q.Pop(ctx, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Pop = %v", err)
	}
	done := make(chan struct{})
	close(done)
	if _, err := q.Pop(context.Background(), done); !errors.Is(err, ErrDone) {
		t.Fatalf("Pop after done = %v", err)
	}
}

func TestManyWaiters(t *testing.T) {
	q := New[int](4)
	const n = 8
	got := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := q.Pop(context.Background(), nil)
			if err == nil {
				got <- v
			}
		}()
	}
	for i := range n {
		q.Push(i, Kept)
	}
	wg.Wait()
	if len(got) != n {
		t.Fatalf("%d of %d waiters woke", len(got), n)
	}
}

func TestSeparateBudgets(t *testing.T) {
	q := New[int](2, 1)
	q.Push(1, 1)
	q.Push(2, 1)
	if q.Push(3, 1) {
		t.Fatal("class 1 over its budget")
	}
	if !q.Push(4, 2) {
		t.Fatal("class 2 refused while class 1 is full")
	}
	if q.Push(5, 2) {
		t.Fatal("class 2 over its budget")
	}
	if q.Push(6, 3) {
		t.Fatal("unknown class accepted")
	}
	if !q.Push(7, Kept) {
		t.Fatal("kept item refused")
	}
}
