package cliargs

import (
	"flag"
	"io"
	"testing"
)

func TestParseLegacyDaemonArgsAllowsFlagsOnEitherSideOfLegacyTriple(t *testing.T) {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rate := fs.Int("rate", 50, "")
	pending := fs.Int("pending", 5, "")
	dummy := fs.Bool("dummy", false, "")

	legacy, err := ParseLegacyDaemonArgs(
		[]string{"--rate", "999", "192.0.2.0/24", "dev", "eth0", "--pending=7", "--dummy"},
		fs,
	)
	if err != nil {
		t.Fatalf("ParseLegacyDaemonArgs() error = %v", err)
	}
	if legacy.Network != "192.0.2.0/24" || legacy.Interface != "eth0" {
		t.Fatalf("legacy = %+v, want network 192.0.2.0/24 and interface eth0", legacy)
	}
	if *rate != 999 || *pending != 7 || !*dummy {
		t.Fatalf("flags parsed as rate=%d pending=%d dummy=%t, want rate=999 pending=7 dummy=true", *rate, *pending, *dummy)
	}
}

func TestParseLegacyDaemonArgsRejectsLeftoverPositionals(t *testing.T) {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Int("rate", 50, "")

	_, err := ParseLegacyDaemonArgs(
		[]string{"192.0.2.0/24", "dev", "eth0", "unexpected", "--rate=999"},
		fs,
	)
	if err == nil {
		t.Fatal("ParseLegacyDaemonArgs() error = nil, want leftover positional error")
	}
}

func TestParseLegacyDaemonArgsSupportsModernFlagOnlySyntax(t *testing.T) {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	network := fs.String("network", "", "")
	iface := fs.String("interface", "", "")

	legacy, err := ParseLegacyDaemonArgs(
		[]string{"--network", "192.0.2.0/24", "--interface", "eth0"},
		fs,
	)
	if err != nil {
		t.Fatalf("ParseLegacyDaemonArgs() error = %v", err)
	}
	if legacy != (LegacyDaemonArgs{}) {
		t.Fatalf("legacy = %+v, want no legacy syntax", legacy)
	}
	if *network != "192.0.2.0/24" || *iface != "eth0" {
		t.Fatalf("modern flags parsed as network=%q interface=%q", *network, *iface)
	}
}

func TestParseLegacyDaemonArgsSkipsDevTriplesWithoutCIDR(t *testing.T) {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rate := fs.Int("rate", 50, "")

	legacy, err := ParseLegacyDaemonArgs(
		[]string{"not-a-network", "dev", "eth0", "--rate=999"},
		fs,
	)
	if err == nil {
		t.Fatal("ParseLegacyDaemonArgs() accepted the leftover malformed positional triple")
	}
	if legacy != (LegacyDaemonArgs{}) {
		t.Fatalf("legacy = %+v after parse error, want zero value", legacy)
	}
	if *rate != 50 {
		t.Fatalf("rate = %d after parse error, want unchanged default", *rate)
	}
}
