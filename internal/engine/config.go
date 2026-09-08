package engine

import (
	"fmt"
	"math"
	"time"
)

// ValidateConfig checks a candidate without changing engine state. Zero disables
// pacing, expiry, or sweeping where applicable; zero MaxPending is valid.
func ValidateConfig(cfg Config) error {
	if cfg.QueueDepth <= 0 {
		return fmt.Errorf("queue_depth must be > 0")
	}
	if cfg.MaxPending < 0 {
		return fmt.Errorf("max_pending must be >= 0")
	}
	for _, field := range []struct {
		name  string
		value int
	}{
		{"arp_age", cfg.ArpAge}, {"learning", cfg.LearnSeconds},
		{"sweep_period", cfg.SweepPeriod}, {"sweep_age", cfg.SweepAge},
	} {
		if field.value < 0 {
			return fmt.Errorf("%s must be >= 0", field.name)
		}
		if int64(field.value) > math.MaxInt64/int64(time.Second) {
			return fmt.Errorf("%s exceeds maximum duration in seconds", field.name)
		}
	}
	for _, field := range []struct {
		name  string
		value float64
	}{
		{"max_rate", cfg.MaxRate}, {"proberate", cfg.Proberate}, {"flood_protection", cfg.FloodProtection},
	} {
		if math.IsNaN(field.value) || math.IsInf(field.value, 0) || field.value < 0 {
			return fmt.Errorf("%s must be finite and >= 0", field.name)
		}
	}
	return nil
}

// rateInterval saturates before float-to-duration conversion, whose overflow
// behavior otherwise depends on the architecture. Positive rates never disable
// throttling, even when the reciprocal exceeds the duration range.
func rateInterval(rate float64) time.Duration {
	if rate <= 0 {
		return 0
	}
	ns := float64(time.Second) / rate
	if ns >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	if ns <= 1 {
		return time.Nanosecond
	}
	return time.Duration(ns)
}
