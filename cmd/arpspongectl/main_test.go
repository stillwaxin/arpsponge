package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMainHelpExitsSuccessfully(t *testing.T) {
	if helpArg := os.Getenv("ARPSPONGECTL_HELPER_ARG"); helpArg != "" {
		os.Args = []string{"arpspongectl", helpArg}
		main()
		return
	}

	for _, helpArg := range []string{"--help", "-h"} {
		t.Run(helpArg, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestMainHelpExitsSuccessfully$")
			cmd.Env = append(os.Environ(), "ARPSPONGECTL_HELPER_ARG="+helpArg)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("arpspongectl %s exited with %v:\n%s", helpArg, err, output)
			}
			if !strings.Contains(string(output), "usage: arpspongectl") {
				t.Fatalf("arpspongectl %s output missing usage:\n%s", helpArg, output)
			}
			if strings.Contains(string(output), "flag: help requested") {
				t.Fatalf("arpspongectl %s leaked flag.ErrHelp:\n%s", helpArg, output)
			}
		})
	}
}

func TestParseGlobalArgsAcceptsSeparatedInterfaceBeforeCommand(t *testing.T) {
	opts, cmd, cmdArgs, err := parseGlobalArgs([]string{"--interface", "eth0", "status"})
	if err != nil {
		t.Fatalf("parseGlobalArgs() error = %v", err)
	}
	if opts.interfaceName != "eth0" {
		t.Fatalf("interface = %q, want eth0", opts.interfaceName)
	}
	if cmd != "status" {
		t.Fatalf("command = %q, want status", cmd)
	}
	if len(cmdArgs) != 0 {
		t.Fatalf("command args = %q, want none", cmdArgs)
	}
}

func TestParseGlobalArgsParsesVersionOnceWithRemainingArguments(t *testing.T) {
	opts, cmd, cmdArgs, err := parseGlobalArgs([]string{"--version", "status"})
	if err != nil {
		t.Fatalf("parseGlobalArgs() error = %v", err)
	}
	if !opts.version {
		t.Fatal("version = false, want true")
	}
	if cmd != "status" {
		t.Fatalf("command = %q, want status", cmd)
	}
	if len(cmdArgs) != 0 {
		t.Fatalf("command args = %q, want none", cmdArgs)
	}
}
