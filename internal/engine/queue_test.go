package engine

import (
	"math"
	"reflect"
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
	ip := uint32(0x0a000001)
	t0 := time.Unix(0, 0)
	tests := []struct {
		name       string
		maxRate    float64
		entries    []queueEntry
		wantDepth  int
		wantRate   float64
		wantQueue  []queueEntry
		checkQueue bool
	}{
		{
			name:      "keeps entries separated by min delta",
			maxRate:   2.0,
			entries:   []queueEntry{{src: 2, ts: t0}, {src: 2, ts: t0.Add(100 * time.Millisecond)}, {src: 2, ts: t0.Add(900 * time.Millisecond)}},
			wantDepth: 2,
			wantRate:  66.6666667,
		},
		{
			name:    "greedily keeps a dense run from one source",
			maxRate: 1.0,
			entries: func() []queueEntry {
				entries := make([]queueEntry, 11)
				for i := range entries {
					entries[i] = queueEntry{src: 2, ts: t0.Add(time.Duration(i) * 500 * time.Millisecond)}
				}
				return entries
			}(),
			wantDepth: 6,
			wantRate:  60.0,
		},
		{
			name:    "filters each source and preserves queue order",
			maxRate: 1.0,
			entries: []queueEntry{
				{src: 2, ts: t0},
				{src: 3, ts: t0.Add(500 * time.Millisecond)},
				{src: 2, ts: t0.Add(500 * time.Millisecond)},
				{src: 3, ts: t0.Add(time.Second)},
				{src: 2, ts: t0.Add(time.Second)},
				{src: 3, ts: t0.Add(1500 * time.Millisecond)},
			},
			wantDepth: 4,
			wantQueue: []queueEntry{
				{src: 2, ts: t0},
				{src: 3, ts: t0.Add(500 * time.Millisecond)},
				{src: 2, ts: t0.Add(time.Second)},
				{src: 3, ts: t0.Add(1500 * time.Millisecond)},
			},
			checkQueue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := NewQueue(20)
			for _, entry := range tt.entries {
				q.Add(ip, entry.src, entry.ts)
			}

			depth := q.Reduce(ip, tt.maxRate)
			if depth != tt.wantDepth {
				t.Fatalf("expected depth %d after reduce, got %d", tt.wantDepth, depth)
			}
			if tt.wantRate > 0 && math.Abs(q.Rate(ip)-tt.wantRate) > 0.01 {
				t.Fatalf("expected rate ~%f after reduce, got %f", tt.wantRate, q.Rate(ip))
			}
			if tt.checkQueue && !reflect.DeepEqual(q.q[ip], tt.wantQueue) {
				t.Fatalf("expected queue %#v after reduce, got %#v", tt.wantQueue, q.q[ip])
			}
		})
	}
}

func TestQueueReduceTinyRateDoesNotOverflow(t *testing.T) {
	q := NewQueue(10)
	q.Add(1, 2, time.Unix(0, 0))
	q.Add(1, 2, time.Unix(1, 0))
	if got := q.Reduce(1, math.SmallestNonzeroFloat64); got != 1 {
		t.Fatalf("tiny flood rate retained %d entries, want 1", got)
	}
}
