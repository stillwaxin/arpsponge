package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStartupConfigValidationPrecedesResources(t *testing.T) {
	overflow := fmt.Sprint(math.MaxInt64/int64(time.Second) + 1)
	for _, tt := range []struct{ flag, value, field string }{
		{"queuedepth", "0", "queue_depth"}, {"queuedepth", "-1", "queue_depth"},
		{"pending", "-1", "max_pending"}, {"age", "-1", "arp_age"},
		{"learning", "-1", "learning"}, {"sweep", "-1/0", "sweep_period"}, {"sweep", "0/-1", "sweep_age"},
		{"age", overflow, "arp_age"}, {"learning", overflow, "learning"},
		{"sweep", overflow + "/0", "sweep_period"}, {"sweep", "0/" + overflow, "sweep_age"},
		{"rate", "-1", "max_rate"}, {"proberate", "-1", "proberate"}, {"flood-protection", "-1", "flood_protection"},
		{"rate", "NaN", "max_rate"}, {"rate", "+Inf", "max_rate"}, {"rate", "-Inf", "max_rate"},
		{"proberate", "NaN", "proberate"}, {"proberate", "+Inf", "proberate"}, {"proberate", "-Inf", "proberate"},
		{"flood-protection", "NaN", "flood_protection"}, {"flood-protection", "+Inf", "flood_protection"}, {"flood-protection", "-Inf", "flood_protection"},
	} {
		t.Run(tt.flag+"/"+tt.value, func(t *testing.T) {
			dir := t.TempDir()
			pid, socket := filepath.Join(dir, "daemon.pid"), filepath.Join(dir, "run", "control.sock")
			args := []string{"--network=192.0.2.0/24", "--interface=arpsponge-invalid-interface", "--pidfile=" + pid, "--control=" + socket, "--" + tt.flag + "=" + tt.value}
			var output bytes.Buffer
			err := runWithIO(args, &output, &output)
			if err == nil || !strings.Contains(err.Error(), tt.field) || strings.Contains(err.Error(), "interface error") {
				t.Fatalf("startup error=%v, want field-specific %s error before interface lookup", err, tt.field)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("invalid configuration created runtime resources: %v, %v", entries, err)
			}
		})
	}
}

func TestStartupAcceptsConfigBoundaries(t *testing.T) {
	for _, rate := range []string{"0", "5e-324"} {
		var output bytes.Buffer
		err := runWithIO([]string{"--network=192.0.2.0/24", "--interface=arpsponge-invalid-interface", "--queuedepth=1", "--pending=0", "--age=0", "--learning=0", "--sweep=0/0", "--rate=0", "--flood-protection=0", "--proberate=" + rate}, &output, &output)
		if err == nil || !strings.Contains(err.Error(), "interface error") {
			t.Fatalf("valid boundary rejected before interface lookup: %v", err)
		}
	}
}
