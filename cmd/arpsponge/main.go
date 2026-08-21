package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"arpsponge/internal/cliargs"
	"arpsponge/internal/control"
	"arpsponge/internal/engine"
	"arpsponge/internal/netutil"
	"arpsponge/internal/packet"
	"arpsponge/internal/platform/linux"
)

var version = "dev"

var errVersionRequested = errors.New("version requested")

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errVersionRequested) {
			fmt.Println(version)
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(args []string) error {
	return runWithIO(args, os.Stdout, os.Stderr)
}

func runWithIO(args []string, stdout io.Writer, stderr io.Writer) (runErr error) {
	flags := flag.NewFlagSet("arpsponge", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	var (
		flagAge            = flags.Int("age", 600, "arp cache age seconds")
		flagVersion        = flags.Bool("version", false, "print version")
		flagArpUpdate      = flags.String("arp-update-method", "none", "arp update method list")
		flagControl        = flags.String("control", "", "control socket path")
		flagDaemon         = flags.Bool("daemon", false, "deprecated no-op; use a service manager")
		flagDummy          = flags.Bool("dummy", false, "do not send packets")
		flagPassive        = flags.Bool("passive", false, "do not send ARP queries")
		flagStatic         = flags.Bool("static", false, "disable automatic sponging")
		flagFloodProtect   = flags.Float64("flood-protection", 3.0, "max source query rate (q/s)")
		flagGratuitous     = flags.Bool("gratuitous", false, "send gratuitous ARP on sponging")
		flagInit           = flags.String("init", "ALIVE", "initial state (ALIVE|DEAD|PENDING|NONE)")
		flagLearning       = flags.Int("learning", 5, "learning seconds")
		flagLogLevel       = flags.String("loglevel", "info", "log level")
		flagLogMask        = flags.String("logmask", "all", "log mask")
		flagPending        = flags.Int("pending", 5, "max pending probes before sponging")
		flagPidfile        = flags.String("pidfile", "", "pid file path")
		flagProberate      = flags.Float64("proberate", 100, "probe rate (q/s)")
		flagQueueDepth     = flags.Int("queuedepth", 1000, "queue depth")
		flagRate           = flags.Float64("rate", 50, "max rate (q/min)")
		flagRundir         = flags.String("rundir", "/run/arpsponge", "runtime directory")
		flagSpongeNetwork  = flags.Bool("sponge-network", false, "sponge network and broadcast")
		flagStatusFile     = flags.String("statusfile", "", "status dump file")
		flagSweep          = flags.String("sweep", "", "sweep period/age (sec/age)")
		flagSweepAtStart   = flags.Bool("sweep-at-start", false, "sweep all at start")
		flagSweepSkipAlive = flags.Bool("sweep-skip-alive", false, "skip alive IPs during sweep")
		flagVerbose        = flags.Int("verbose", 0, "verbose logging")
		flagNetwork        = flags.String("network", "", "network prefix (CIDR)")
		flagInterface      = flags.String("interface", "", "interface name")
		flagMAC            = flags.String("mac", "", "override source mac address")
		flagPermissions    = flags.String("permissions", "", "socket permissions user:group:mode")
	)
	legacy, err := cliargs.ParseLegacyDaemonArgs(args, flags)
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.Copy(stdout, &flagOutput)
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w\nrun \"arpsponge --help\" for usage", err)
	}
	if *flagDaemon {
		fmt.Fprintln(stderr, "--daemon is deprecated and ignored; use a service manager")
	}

	if *flagVersion {
		return errVersionRequested
	}

	network := *flagNetwork
	iface := *flagInterface
	if network == "" || iface == "" {
		if legacy == (cliargs.LegacyDaemonArgs{}) {
			return errors.New("usage: arpsponge NETPREFIX/LEN dev IFNAME [options]")
		}
		if network == "" {
			network = legacy.Network
		}
		if iface == "" {
			iface = legacy.Interface
		}
	}

	netCIDR, netIP, broadcast, prefixLen, err := netutil.ParseCIDRString(network)
	if err != nil {
		return fmt.Errorf("invalid network: %w", err)
	}
	initState, err := parseInitState(*flagInit)
	if err != nil {
		return err
	}
	updateFlags, err := engine.ParseUpdateFlags(*flagArpUpdate)
	if err != nil {
		return err
	}
	sweepPeriod, sweepAge, err := parseSweep(*flagSweep)
	if err != nil {
		return err
	}

	ifaceInfo, err := linux.GetInterfaceInfo(iface)
	if err != nil {
		return fmt.Errorf("interface error: %w", err)
	}
	myMAC := ifaceInfo.MAC
	if *flagMAC != "" {
		overrideMAC, err := packet.ParseMAC(*flagMAC)
		if err != nil {
			return fmt.Errorf("invalid mac: %w", err)
		}
		myMAC = overrideMAC
	}

	logLevel, err := engine.ParseLogLevel(*flagLogLevel)
	if err != nil {
		return err
	}
	if *flagVerbose > 0 {
		logLevel = engine.LevelDebug
	}
	logMask, err := engine.ParseEventMask(*flagLogMask, engine.EventAll)
	if err != nil {
		return err
	}
	logger := control.NewLogger(1024, logLevel, logMask)

	cfg := engine.DefaultConfig()
	cfg.QueueDepth = *flagQueueDepth
	cfg.MaxRate = *flagRate
	cfg.ArpAge = *flagAge
	cfg.MaxPending = *flagPending
	cfg.Proberate = *flagProberate
	cfg.FloodProtection = *flagFloodProtect
	cfg.InitState = initState
	cfg.LearnSeconds = *flagLearning
	cfg.LogLevel = logLevel
	cfg.LogMask = logMask
	cfg.Dummy = *flagDummy
	cfg.Passive = *flagPassive
	cfg.Static = *flagStatic
	cfg.Gratuitous = *flagGratuitous
	cfg.SpongeNet = *flagSpongeNetwork
	cfg.SweepPeriod = sweepPeriod
	cfg.SweepAge = sweepAge
	cfg.SweepSkipAlive = *flagSweepSkipAlive
	cfg.ArpUpdateFlags = updateFlags

	var pidFile *pidFile
	if *flagPidfile != "" {
		pidFile, err = acquirePIDFile(*flagPidfile)
		if err != nil {
			return fmt.Errorf("pidfile error: %w", err)
		}
		defer func() {
			if err := pidFile.Close(); err != nil && runErr == nil {
				runErr = err
			}
		}()
	}

	capture, err := linux.OpenCapture(iface, 512, true, 5*time.Millisecond)
	if err != nil {
		return fmt.Errorf("pcap open failed: %w", err)
	}

	eng := engine.New(cfg, iface, netCIDR, netIP, broadcast, prefixLen, ifaceInfo.PrimaryIP, myMAC, ifaceInfo.AllIPs, capture, logger)
	ctx, cancel := context.WithCancel(context.Background())
	var captureWG sync.WaitGroup
	defer func() {
		cancel()
		eng.Stop()
		captureWG.Wait()
		capture.Close()
	}()
	if *flagSweepAtStart {
		eng.SetSweepAtStart()
	}

	socketPath := *flagControl
	if socketPath == "" {
		socketPath = filepath.Join(*flagRundir, iface, "control.sock")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("cannot create rundir: %w", err)
	}
	owner, group, perm, err := parsePerms(*flagPermissions)
	if err != nil {
		return fmt.Errorf("permissions error: %w", err)
	}
	listener, err := linux.ListenUnix(socketPath, owner, group, perm)
	if err != nil {
		return fmt.Errorf("control socket error: %w", err)
	}
	defer listener.Close()

	srv := control.NewServer(eng, logger)
	httpServer := newControlHTTPServer(srv.Handler())
	defer func() {
		if err := shutdownControlHTTPServer(httpServer); err != nil && runErr == nil {
			runErr = err
		}
	}()
	serverErrs := make(chan error, 1)
	go func() {
		serverErrs <- httpServer.Serve(listener)
	}()

	captureWG.Add(1)
	go func() {
		defer captureWG.Done()
		_ = capture.Run(ctx, eng.HandlePacket)
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, signalSet()...)
	defer signal.Stop(sigs)

	for {
		select {
		case <-ticker.C:
			eng.Tick(time.Now())
		case err := <-serverErrs:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("control server: %w", err)
			}
			return nil
		case sig := <-sigs:
			if isDumpSignal(sig) {
				if *flagStatusFile != "" {
					_ = dumpStatus(*flagStatusFile, eng)
				}
				continue
			}
			return
		}
	}
}

func parseInitState(s string) (engine.State, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ALIVE":
		return engine.StateAlive, nil
	case "DEAD":
		return engine.StateDead, nil
	case "PENDING":
		return engine.Pending(0), nil
	case "NONE":
		return engine.StateNone, nil
	default:
		return engine.StateNone, fmt.Errorf("invalid init state %q (want ALIVE, DEAD, PENDING, or NONE)", s)
	}
}

func parseSweep(spec string) (int, int, error) {
	if strings.TrimSpace(spec) == "" {
		return 0, 0, nil
	}
	parts := strings.Split(spec, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid sweep %q (want period/age in seconds)", spec)
	}
	period, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid sweep period %q: %w", parts[0], err)
	}
	age, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid sweep age %q: %w", parts[1], err)
	}
	if period < 0 || age < 0 {
		return 0, 0, fmt.Errorf("invalid sweep %q: period and age must be >= 0", spec)
	}
	return period, age, nil
}

func parsePerms(spec string) (string, string, os.FileMode, error) {
	if strings.TrimSpace(spec) == "" {
		return "", "", 0o660, nil
	}
	parts := strings.Split(spec, ":")
	if len(parts) != 3 {
		return "", "", 0, errors.New("expected user:group:mode")
	}
	owner := parts[0]
	group := parts[1]
	modeVal, err := strconv.ParseUint(parts[2], 8, 32)
	if err != nil {
		return "", "", 0, err
	}
	return owner, group, os.FileMode(modeVal), nil
}

func dumpStatus(path string, eng *engine.Engine) error {
	status := struct {
		Status engine.Status     `json:"status"`
		IP     []engine.IPState  `json:"ip"`
		ARP    []engine.ARPState `json:"arp"`
	}{
		Status: eng.Status(),
		IP:     eng.SnapshotState(),
		ARP:    eng.SnapshotARP(),
	}
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
