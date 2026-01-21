package engine

import (
	"sort"
	"time"
)

type queueEntry struct {
	src uint32
	ts  time.Time
}

type Queue struct {
	maxDepth int
	q        map[uint32][]queueEntry
}

func NewQueue(maxDepth int) *Queue {
	if maxDepth <= 0 {
		maxDepth = 1
	}
	return &Queue{maxDepth: maxDepth, q: make(map[uint32][]queueEntry)}
}

func (q *Queue) MaxDepth() int {
	return q.maxDepth
}

func (q *Queue) SetMaxDepth(depth int) {
	if depth <= 0 {
		depth = 1
	}
	q.maxDepth = depth
	for ip := range q.q {
		entries := q.q[ip]
		if len(entries) > depth {
			q.q[ip] = entries[len(entries)-depth:]
		}
	}
}

func (q *Queue) ClearAll() {
	q.q = make(map[uint32][]queueEntry)
}

func (q *Queue) Clear(ip uint32) {
	delete(q.q, ip)
}

func (q *Queue) Add(ip uint32, src uint32, ts time.Time) {
	entries := q.q[ip]
	entries = append(entries, queueEntry{src: src, ts: ts})
	if len(entries) > q.maxDepth {
		entries = entries[len(entries)-q.maxDepth:]
	}
	q.q[ip] = entries
}

func (q *Queue) Depth(ip uint32) int {
	return len(q.q[ip])
}

func (q *Queue) IsFull(ip uint32) bool {
	return len(q.q[ip]) >= q.maxDepth
}

func (q *Queue) Rate(ip uint32) float64 {
	entries := q.q[ip]
	if len(entries) <= 1 {
		return 0
	}
	first := entries[0].ts
	last := entries[len(entries)-1].ts
	delta := last.Sub(first).Seconds()
	if delta <= 0 {
		return 0
	}
	n := float64(len(entries) - 1)
	return (n / delta) * 60.0
}

func (q *Queue) GetQueue(ip uint32) []queueEntry {
	entries := q.q[ip]
	out := make([]queueEntry, len(entries))
	copy(out, entries)
	return out
}

func (q *Queue) Reduce(ip uint32, maxRate float64) int {
	entries := q.q[ip]
	if len(entries) == 0 {
		return 0
	}
	if maxRate <= 0 {
		return len(entries)
	}
	minDelta := time.Duration(float64(time.Second) / maxRate)
	if minDelta <= 0 {
		return len(entries)
	}

	sorted := make([]queueEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].src == sorted[j].src {
			return sorted[i].ts.Before(sorted[j].ts)
		}
		return sorted[i].src < sorted[j].src
	})

	var reduced []queueEntry
	var prev *queueEntry
	for i := range sorted {
		entry := &sorted[i]
		if prev != nil {
			if entry.src != prev.src || entry.ts.Sub(prev.ts) >= minDelta {
				reduced = append(reduced, *prev)
			}
		}
		prev = entry
	}
	if prev != nil {
		reduced = append(reduced, *prev)
	}

	sort.Slice(reduced, func(i, j int) bool {
		return reduced[i].ts.Before(reduced[j].ts)
	})
	q.q[ip] = reduced
	return len(reduced)
}
