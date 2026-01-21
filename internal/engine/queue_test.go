package engine

import (
	"math"
	"testing"
	"time"
)

func TestQueueRate(t *testing.T) {
	q := NewQueue(10)
	ip := uint32(0x0a000001)
	src := uint32(0x0a000002)
	q.Add(ip, src, time.Unix(0, 0))
	q.Add(ip, src, time.Unix(1, 0))
	q.Add(ip, src, time.Unix(2, 0))

	rate := q.Rate(ip)
	if math.Abs(rate-60.0) > 0.01 {
		t.Fatalf("expected rate ~60, got %f", rate)
	}
}

func TestQueueReduce(t *testing.T) {
	q := NewQueue(10)
	ip := uint32(0x0a000001)
	src := uint32(0x0a000002)
	t0 := time.Unix(0, 0)
	q.Add(ip, src, t0)
	q.Add(ip, src, t0.Add(100*time.Millisecond))
	q.Add(ip, src, t0.Add(900*time.Millisecond))

	depth := q.Reduce(ip, 2.0)
	if depth != 2 {
		t.Fatalf("expected depth 2 after reduce, got %d", depth)
	}
}
