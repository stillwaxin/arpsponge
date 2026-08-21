package cliargs

import (
	"flag"
	"fmt"
	"net"
	"strings"
)

// LegacyDaemonArgs is the positional network and interface pair accepted by
// the daemon's legacy NET dev IFACE syntax.
type LegacyDaemonArgs struct {
	Network   string
	Interface string
}

// ParseLegacyDaemonArgs removes one legacy NET dev IFACE triple before handing
// the remaining arguments to the flag parser. This lets standard flags appear
// on either side of the legacy syntax without silently accepting positionals.
func ParseLegacyDaemonArgs(args []string, flags *flag.FlagSet) (LegacyDaemonArgs, error) {
	legacy, flagArgs := extractLegacyDaemonArgs(args)
	if err := flags.Parse(flagArgs); err != nil {
		return LegacyDaemonArgs{}, err
	}
	if remaining := flags.Args(); len(remaining) > 0 {
		return LegacyDaemonArgs{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(remaining, " "))
	}
	return legacy, nil
}

func extractLegacyDaemonArgs(args []string) (LegacyDaemonArgs, []string) {
	for i := 0; i+2 < len(args); i++ {
		if args[i+1] != "dev" {
			continue
		}
		if _, _, err := net.ParseCIDR(args[i]); err != nil {
			continue
		}
		legacy := LegacyDaemonArgs{Network: args[i], Interface: args[i+2]}
		flagArgs := make([]string, 0, len(args)-3)
		flagArgs = append(flagArgs, args[:i]...)
		flagArgs = append(flagArgs, args[i+3:]...)
		return legacy, flagArgs
	}
	return LegacyDaemonArgs{}, args
}
