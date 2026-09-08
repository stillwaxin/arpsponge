package engine

import (
	"context"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

type invalidConfigCase struct {
	name   string
	field  string
	update func(*Config)
}

func invalidConfigCases() []invalidConfigCase {
	cases := []invalidConfigCase{
		{"zero queue", "queue_depth", func(c *Config) { c.QueueDepth = 0 }},
		{"negative queue", "queue_depth", func(c *Config) { c.QueueDepth = -1 }},
		{"negative pending", "max_pending", func(c *Config) { c.MaxPending = -1 }},
	}
	for _, field := range []string{"arp_age", "learning", "sweep_period", "sweep_age"} {
		field := field
		for _, value := range []int{-1, int(math.MaxInt64/int64(time.Second)) + 1} {
			value := value
			cases = append(cases, invalidConfigCase{field + "/" + time.Duration(value).String(), field, func(c *Config) {
				switch field {
				case "arp_age":
					c.ArpAge = value
				case "learning":
					c.LearnSeconds = value
				case "sweep_period":
					c.SweepPeriod = value
				case "sweep_age":
					c.SweepAge = value
				}
			}})
		}
	}
	for _, field := range []string{"max_rate", "proberate", "flood_protection"} {
		field := field
		for _, value := range []float64{-1, math.NaN(), math.Inf(1), math.Inf(-1)} {
			value := value
			cases = append(cases, invalidConfigCase{field + "/" + strings.TrimSpace(formatConfigFloat(value)), field, func(c *Config) {
				switch field {
				case "max_rate":
					c.MaxRate = value
				case "proberate":
					c.Proberate = value
				case "flood_protection":
					c.FloodProtection = value
				}
			}})
		}
	}
	return cases
}

func formatConfigFloat(value float64) string {
	if math.IsNaN(value) {
		return "NaN"
	}
	if math.IsInf(value, 1) {
		return "+Inf"
	}
	if math.IsInf(value, -1) {
		return "-Inf"
	}
	return "negative"
}

func TestInvalidConfigUpdatesAreAtomic(t *testing.T) {
	for _, tt := range invalidConfigCases() {
		t.Run(tt.name, func(t *testing.T) {
			eng, _ := newTestEngine(t)
			ip := mustIP(t, "10.0.0.88")
			eng.setARPEntryLocked(ip, eng.myMAC, 10)
			eng.queue.Add(ip, ip, time.Now())
			before := eng.Config()
			expiry := eng.nextARPExpiry
			intervals := eng.queryPacer.interval
			err := eng.UpdateConfig(func(c *Config) error {
				c.QueueDepth = 2
				c.LearnSeconds = 12
				c.ArpAge = 10
				c.Proberate = 22
				c.SweepPeriod = 100
				tt.update(c)
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("got %v, want %s validation error", err, tt.field)
			}
			if !reflect.DeepEqual(eng.Config(), before) || eng.queue.MaxDepth() != before.QueueDepth || eng.learningLeft != 0 || eng.nextARPExpiry != expiry || eng.queryPacer.interval != intervals || !eng.nextSweep.IsZero() {
				t.Fatal("invalid update mutated engine configuration or derived state")
			}
		})
	}
}

func TestConfigZeroBoundaries(t *testing.T) {
	eng, _ := newTestEngine(t)
	zero := Config{QueueDepth: 1, InitState: StateNone}
	if err := eng.UpdateConfig(func(c *Config) error { *c = zero; return nil }); err != nil {
		t.Fatalf("zero boundaries rejected: %v", err)
	}
	if eng.queryPacer.interval != 0 || !eng.nextSweep.IsZero() {
		t.Fatal("zero pacing or sweeping not disabled")
	}
	ip := mustIP(t, "10.0.0.88")
	_ = eng.SetIPState(ip, Pending(0), eng.myMAC)
	eng.probePending(context.Background(), time.Now())
	got, _ := eng.GetIPState(ip)
	if got.State != "DEAD" {
		t.Fatalf("zero pending should sponge immediately, got %s", got.State)
	}
}

func TestTinyProbeRateSaturatesAndDoesNotPrematurelyAgeSweep(t *testing.T) {
	var pacer queryPacer
	pacer.configure(math.SmallestNonzeroFloat64)
	if pacer.interval != time.Duration(math.MaxInt64) {
		t.Fatalf("tiny rate interval=%v, want maximum duration", pacer.interval)
	}
	now := time.Now()
	pacer.sweepWaiters = []*queryPacerSweepWaiter{{since: now.Add(-time.Second)}}
	if pacer.oldestAgedSweepWaiterLocked(now) != nil {
		t.Fatal("overflow prematurely aged sweep waiter")
	}
	pacer.configure(1e-9)
	if pacer.oldestAgedSweepWaiterLocked(now) != nil {
		t.Fatal("ten-interval overflow prematurely aged sweep waiter")
	}
	ctx, cancel := context.WithCancel(context.Background())
	if !pacer.wait(ctx, true) {
		t.Fatal("first permit unavailable")
	}
	done := make(chan bool, 1)
	go func() { done <- pacer.wait(ctx, true) }()
	cancel()
	select {
	case granted := <-done:
		if granted {
			t.Fatal("canceled tiny-rate waiter got permit")
		}
	case <-time.After(time.Second):
		t.Fatal("tiny-rate waiter did not cancel")
	}
}

func TestValidateConfig(t *testing.T) {
	for _, tt := range invalidConfigCases() {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.update(&cfg)
			err := ValidateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("got %v, want %s validation error", err, tt.field)
			}
		})
	}
	for _, cfg := range []Config{DefaultConfig(), {QueueDepth: 1}, {QueueDepth: 1, ArpAge: int(math.MaxInt64 / int64(time.Second)), LearnSeconds: int(math.MaxInt64 / int64(time.Second)), SweepPeriod: int(math.MaxInt64 / int64(time.Second)), SweepAge: int(math.MaxInt64 / int64(time.Second)), Proberate: math.SmallestNonzeroFloat64, MaxRate: math.MaxFloat64, FloodProtection: math.SmallestNonzeroFloat64}} {
		if err := ValidateConfig(cfg); err != nil {
			t.Fatalf("valid boundary rejected: %v", err)
		}
	}
}

func TestRateIntervalBoundaries(t *testing.T) {
	for _, tt := range []struct {
		rate float64
		want time.Duration
	}{{0, 0}, {1, time.Second}, {math.SmallestNonzeroFloat64, time.Duration(math.MaxInt64)}, {math.MaxFloat64, time.Nanosecond}} {
		if got := rateInterval(tt.rate); got != tt.want {
			t.Fatalf("rate=%v interval=%v want %v", tt.rate, got, tt.want)
		}
	}
}
