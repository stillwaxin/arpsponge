package control

import (
	"fmt"
	"os"
	"sync"
	"time"

	"arpsponge/internal/engine"
)

type LogEntry struct {
	Time  int64  `json:"time"`
	Level string `json:"level"`
	Event string `json:"event"`
	PID   int    `json:"pid"`
	Msg   string `json:"msg"`
}

type Logger struct {
	mu          sync.Mutex
	entries     []LogEntry
	maxEntries  int
	subscribers map[chan LogEntry]struct{}
	level       engine.LogLevel
	mask        engine.EventMask
}

func NewLogger(maxEntries int, level engine.LogLevel, mask engine.EventMask) *Logger {
	if maxEntries <= 0 {
		maxEntries = 256
	}
	return &Logger{
		entries:     make([]LogEntry, 0, maxEntries),
		maxEntries:  maxEntries,
		subscribers: make(map[chan LogEntry]struct{}),
		level:       level,
		mask:        mask,
	}
}

func (l *Logger) SetLevel(level engine.LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) SetMask(mask engine.EventMask) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.mask = mask
}

func (l *Logger) Logf(level engine.LogLevel, event engine.EventMask, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level > l.level || (event&l.mask) == 0 {
		return
	}
	msg := fmt.Sprintf(format, args...)
	entry := LogEntry{
		Time:  time.Now().Unix(),
		Level: level.String(),
		Event: eventName(event),
		PID:   os.Getpid(),
		Msg:   msg,
	}
	l.entries = append(l.entries, entry)
	if len(l.entries) > l.maxEntries {
		l.entries = l.entries[len(l.entries)-l.maxEntries:]
	}
	for ch := range l.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
}

func (l *Logger) Tail(n int) []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.entries) {
		n = len(l.entries)
	}
	out := make([]LogEntry, n)
	copy(out, l.entries[len(l.entries)-n:])
	return out
}

func (l *Logger) Subscribe() (<-chan LogEntry, func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ch := make(chan LogEntry, 32)
	l.subscribers[ch] = struct{}{}
	cancel := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		delete(l.subscribers, ch)
		close(ch)
	}
	return ch, cancel
}

func eventName(event engine.EventMask) string {
	switch event {
	case engine.EventIO:
		return "io"
	case engine.EventAlien:
		return "alien"
	case engine.EventSpoof:
		return "spoof"
	case engine.EventStatic:
		return "static"
	case engine.EventSponge:
		return "sponge"
	case engine.EventCtl:
		return "ctl"
	case engine.EventState:
		return "state"
	default:
		return "unknown"
	}
}
