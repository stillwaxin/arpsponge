//go:build !windows

package main

import (
	"os"
	"syscall"
)

func signalSet() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1}
}

func isDumpSignal(sig os.Signal) bool {
	return sig == syscall.SIGHUP || sig == syscall.SIGUSR1
}
