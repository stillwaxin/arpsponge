package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"arpsponge/internal/netutil"
	"arpsponge/internal/packet"
)

type nopLogger struct{}

func (nopLogger) Logf(LogLevel, EventMask, string, ...any) {}

type fakeSender struct {
	sent int
	last packet.ARP
}

func (f *fakeSender) SendARP(arp packet.ARP, _ packet.MAC, _ packet.MAC) error {
	f.sent++
	f.last = arp
	return nil
}

func newTestEngine(t *testing.T) (*Engine, *fakeSender) {
	return newTestEngineWithLogger(t, nopLogger{})
}

func newTestEngineWithLogger(t *testing.T, logger Logger) (*Engine, *fakeSender) {
	t.Helper()
	netCIDR, netIP, broadcast, prefixLen, err := netutil.ParseCIDRString("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	myIP, _ := netutil.ParseIPv4String("10.0.0.1")
	mac := packet.MustParseMAC("aa:bb:cc:dd:ee:ff")
	cfg := DefaultConfig()
	cfg.InitState = StateNone
	cfg.LearnSeconds = 0
	sender := &fakeSender{}
	eng := New(cfg, "eth0", netCIDR, netIP, broadcast, prefixLen, myIP, mac, []uint32{myIP}, sender, logger)
	return eng, sender
}

func TestHandleARPSetPending(t *testing.T) {
	eng, _ := newTestEngine(t)
	request := packet.Packet{
		SrcMAC:    packet.MustParseMAC("00:11:22:33:44:55"),
		DstMAC:    packet.MustParseMAC("ff:ff:ff:ff:ff:ff"),
		EtherType: packet.EtherTypeARP,
		ARP: &packet.ARP{
			Opcode:    packet.ARPOpRequest,
			SenderMAC: packet.MustParseMAC("00:11:22:33:44:55"),
			SenderIP:  mustIP(t, "10.0.0.2"),
			TargetMAC: packet.MustParseMAC("00:00:00:00:00:00"),
			TargetIP:  mustIP(t, "10.0.0.5"),
		},
	}
	eng.HandlePacket(request)

	state, ok := eng.GetIPState(mustIP(t, "10.0.0.5"))
	if !ok {
		t.Fatalf("expected state to be set")
	}
	if state.State != "PENDING(0)" {
		t.Fatalf("expected pending state, got %s", state.State)
	}
}

func TestHandleARPReplyForDead(t *testing.T) {
	eng, sender := newTestEngine(t)
	ip := mustIP(t, "10.0.0.9")
	if err := eng.SetIPState(ip, StateDead, packet.MAC{}); err != nil {
		t.Fatalf("set dead: %v", err)
	}

	request := packet.Packet{
		SrcMAC:    packet.MustParseMAC("00:11:22:33:44:55"),
		DstMAC:    packet.MustParseMAC("ff:ff:ff:ff:ff:ff"),
		EtherType: packet.EtherTypeARP,
		ARP: &packet.ARP{
			Opcode:    packet.ARPOpRequest,
			SenderMAC: packet.MustParseMAC("00:11:22:33:44:55"),
			SenderIP:  mustIP(t, "10.0.0.2"),
			TargetMAC: packet.MustParseMAC("00:00:00:00:00:00"),
			TargetIP:  ip,
		},
	}
	eng.HandlePacket(request)

	if sender.sent == 0 {
		t.Fatalf("expected a reply to be sent")
	}
	if sender.last.Opcode != packet.ARPOpReply {
		t.Fatalf("expected reply opcode, got %d", sender.last.Opcode)
	}
}

func TestTickExpiresStaleARPEntriesAtConfiguredAge(t *testing.T) {
	eng, _ := newTestEngine(t)
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.ArpAge = 10
		return nil
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	staleIP := mustIP(t, "10.0.0.20")
	freshIP := mustIP(t, "10.0.0.21")
	eng.mu.Lock()
	eng.setARPEntryLocked(staleIP, packet.MustParseMAC("00:11:22:33:44:20"), 989)
	eng.setARPEntryLocked(freshIP, packet.MustParseMAC("00:11:22:33:44:21"), 991)
	eng.mu.Unlock()
	eng.ForceLearning(1)

	eng.Tick(time.Unix(1000, 0))

	if _, ok := eng.GetARPEntry(staleIP); ok {
		t.Fatal("stale ARP entry was not expired")
	}
	if _, ok := eng.GetARPEntry(freshIP); !ok {
		t.Fatal("fresh ARP entry was expired")
	}
}

func TestTickKeepsARPEntriesWhenExpiryDisabled(t *testing.T) {
	for _, age := range []int{0} {
		t.Run(fmt.Sprintf("age=%d", age), func(t *testing.T) {
			eng, _ := newTestEngine(t)
			if err := eng.UpdateConfig(func(cfg *Config) error {
				cfg.ArpAge = age
				return nil
			}); err != nil {
				t.Fatalf("update config: %v", err)
			}
			ip := mustIP(t, "10.0.0.22")
			eng.mu.Lock()
			eng.setARPEntryLocked(ip, packet.MustParseMAC("00:11:22:33:44:22"), 1)
			eng.mu.Unlock()

			eng.Tick(time.Unix(1000, 0))

			if _, ok := eng.GetARPEntry(ip); !ok {
				t.Fatalf("ARP entry expired with arp_age=%d", age)
			}
		})
	}
}

func TestARPExpiryRefreshSurvivesOriginalDeadline(t *testing.T) {
	eng, _ := newTestEngine(t)
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.ArpAge = 10
		return nil
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	ip := mustIP(t, "10.0.0.23")
	firstMAC := packet.MustParseMAC("00:11:22:33:44:23")
	refreshedMAC := packet.MustParseMAC("00:11:22:33:44:24")
	eng.mu.Lock()
	eng.setARPEntryLocked(ip, firstMAC, 100)
	eng.setARPEntryLocked(ip, refreshedMAC, 105)
	eng.mu.Unlock()

	eng.Tick(time.Unix(111, 0))
	entry, ok := eng.GetARPEntry(ip)
	if !ok || entry.MAC != refreshedMAC.String() {
		t.Fatalf("refreshed entry at original deadline = %#v, %t; want refreshed MAC", entry, ok)
	}

	eng.Tick(time.Unix(116, 0))
	if _, ok := eng.GetARPEntry(ip); ok {
		t.Fatal("refreshed entry survived its own expiry deadline")
	}
}

func TestARPExpiryIndexRemainsBoundedAcrossRefreshes(t *testing.T) {
	eng, _ := newTestEngine(t)
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.ArpAge = 600
		return nil
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}

	ip := mustIP(t, "10.0.0.24")
	mac := packet.MustParseMAC("00:11:22:33:44:24")
	const firstLearnedAt int64 = 1000
	const refreshes int64 = 600
	for offset := int64(0); offset < refreshes; offset++ {
		eng.mu.Lock()
		eng.setARPEntryLocked(ip, mac, firstLearnedAt+offset)
		eng.mu.Unlock()
	}

	firstDeadline := firstLearnedAt + int64(eng.cfg.ArpAge) + 1
	lastLearnedAt := firstLearnedAt + refreshes - 1
	lastDeadline := lastLearnedAt + int64(eng.cfg.ArpAge) + 1
	eng.mu.Lock()
	buckets := len(eng.arpExpiry)
	records := 0
	targetRecords := 0
	for _, bucket := range eng.arpExpiry {
		records += len(bucket)
		if _, ok := bucket[ip]; ok {
			targetRecords++
		}
	}
	liveEntries := len(eng.arpTable)
	nextExpiry := eng.nextARPExpiry
	eng.mu.Unlock()
	if targetRecords != 1 || records != liveEntries || nextExpiry != lastDeadline {
		t.Fatalf("expiry index after %d refreshes = %d buckets, %d records for %d live entries, %d records for target, next %d; want one target record and next %d", refreshes, buckets, records, liveEntries, targetRecords, nextExpiry, lastDeadline)
	}

	eng.mu.Lock()
	eng.expireARPEntriesLocked(firstDeadline)
	_, aliveAtOldDeadline := eng.arpTable[ip]
	eng.expireARPEntriesLocked(lastDeadline)
	_, aliveAtNewDeadline := eng.arpTable[ip]
	eng.mu.Unlock()
	if !aliveAtOldDeadline {
		t.Fatal("refreshed ARP entry expired at its original deadline")
	}
	if aliveAtNewDeadline {
		t.Fatal("refreshed ARP entry survived its latest deadline")
	}
}

func TestIncrPendingLockedDoesNotResurrectAliveAddress(t *testing.T) {
	eng, _ := newTestEngine(t)
	ip := mustIP(t, "10.0.0.30")
	if err := eng.SetIPState(ip, StateAlive, packet.MustParseMAC("00:11:22:33:44:30")); err != nil {
		t.Fatalf("set alive: %v", err)
	}

	eng.mu.Lock()
	eng.incrPendingLocked(ip)
	eng.mu.Unlock()

	state, ok := eng.GetIPState(ip)
	if !ok {
		t.Fatal("address state disappeared")
	}
	if state.State != "ALIVE" {
		t.Fatalf("alive address was resurrected as %s", state.State)
	}
}

func TestProbePendingMarksDeadAtConfiguredCycle(t *testing.T) {
	eng, sender := newTestEngine(t)
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.MaxPending = 2
		cfg.Proberate = 0
		return nil
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	ip := mustIP(t, "10.0.0.31")
	if err := eng.SetIPState(ip, Pending(0), packet.MAC{}); err != nil {
		t.Fatalf("set pending: %v", err)
	}

	for cycle, wantState := range []string{"PENDING(1)", "PENDING(2)"} {
		eng.probePending(context.Background(), time.Unix(int64(1000+cycle), 0))
		state, ok := eng.GetIPState(ip)
		if !ok {
			t.Fatalf("cycle %d: address state disappeared", cycle+1)
		}
		if state.State != wantState {
			t.Fatalf("cycle %d: got %s, want %s", cycle+1, state.State, wantState)
		}
		if sender.sent != cycle+1 {
			t.Fatalf("cycle %d: sent %d probes, want %d", cycle+1, sender.sent, cycle+1)
		}
	}

	eng.probePending(context.Background(), time.Unix(1002, 0))
	state, ok := eng.GetIPState(ip)
	if !ok {
		t.Fatal("address state disappeared on exhausted cycle")
	}
	if state.State != "DEAD" {
		t.Fatalf("exhausted cycle: got %s, want DEAD", state.State)
	}
	if sender.sent != 2 {
		t.Fatalf("exhausted cycle sent %d probes, want 2", sender.sent)
	}
}

func TestProbePendingSkipsAddressClearedAfterSnapshot(t *testing.T) {
	eng, _ := newTestEngine(t)
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.Proberate = 0
		return nil
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	sender := newBlockingProbeSender()
	eng.sender = sender

	firstIP := mustIP(t, "10.0.0.32")
	secondIP := mustIP(t, "10.0.0.33")
	for _, ip := range []uint32{firstIP, secondIP} {
		if err := eng.SetIPState(ip, Pending(0), packet.MAC{}); err != nil {
			t.Fatalf("set pending %s: %v", netutil.IPv4String(ip), err)
		}
	}

	done := make(chan struct{})
	go func() {
		eng.probePending(context.Background(), time.Unix(1000, 0))
		close(done)
	}()

	var clearedIP uint32
	select {
	case probedIP := <-sender.first:
		if probedIP == firstIP {
			clearedIP = secondIP
		} else {
			clearedIP = firstIP
		}
	case <-time.After(time.Second):
		t.Fatal("first probe did not start")
	}
	cleared := make(chan struct{})
	go func() {
		eng.ClearIPState(clearedIP)
		close(cleared)
	}()
	select {
	case <-cleared:
		sender.Release()
		t.Fatal("clear returned while a pending probe send was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	sender.Release()
	select {
	case <-cleared:
	case <-time.After(time.Second):
		t.Fatal("clear did not finish after the pending probe send")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending probe pass did not finish")
	}

	if _, ok := eng.GetIPState(clearedIP); ok {
		t.Fatalf("cleared address %s was restored by the stale probe snapshot", netutil.IPv4String(clearedIP))
	}
	if got := sender.Count(); got != 1 {
		t.Fatalf("sent %d probes, want only the address processed before clear", got)
	}
}

func TestPendingProbeCannotSendOrRecreateMetadataAfterClear(t *testing.T) {
	for _, tt := range []struct {
		name  string
		clear func(*Engine, uint32)
	}{
		{name: "single address", clear: func(eng *Engine, ip uint32) { eng.ClearIPState(ip) }},
		{name: "all addresses", clear: func(eng *Engine, _ uint32) { eng.ClearAllState() }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			eng, _ := newTestEngine(t)
			if err := eng.UpdateConfig(func(cfg *Config) error {
				cfg.Proberate = 10
				return nil
			}); err != nil {
				t.Fatalf("update config: %v", err)
			}
			sender := newFirstTargetSender()
			eng.sender = sender

			ips := []uint32{mustIP(t, "10.0.0.34"), mustIP(t, "10.0.0.35")}
			for _, ip := range ips {
				if err := eng.SetIPState(ip, Pending(0), packet.MAC{}); err != nil {
					t.Fatalf("set pending %s: %v", netutil.IPv4String(ip), err)
				}
			}

			done := make(chan struct{})
			go func() {
				eng.probePending(context.Background(), time.Unix(1000, 0))
				close(done)
			}()

			var firstIP uint32
			select {
			case firstIP = <-sender.first:
			case <-time.After(time.Second):
				t.Fatal("first pending probe was not sent")
			}
			staleIP := ips[0]
			if staleIP == firstIP {
				staleIP = ips[1]
			}
			waitForPendingPacer(t, eng)

			tt.clear(eng, staleIP)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("pending probe pass did not finish")
			}
			if got := sender.Count(); got != 1 {
				t.Fatalf("sent %d probes, want no stale probe after clear", got)
			}
			eng.mu.Lock()
			_, hasState := eng.state[staleIP]
			_, hasAtime := eng.stateAtime[staleIP]
			eng.mu.Unlock()
			if hasState || hasAtime {
				t.Fatalf("clear left stale metadata: state=%t atime=%t", hasState, hasAtime)
			}
		})
	}
}

func TestLazyInitialStateReadsArePure(t *testing.T) {
	for _, tt := range []struct {
		name string
		init State
		want string
	}{
		{name: "alive", init: StateAlive, want: "ALIVE"},
		{name: "pending", init: Pending(0), want: "PENDING(0)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.InitState = tt.init
			cfg.LearnSeconds = 0

			started := time.Now()
			eng, _ := newTestEngineForCIDR(t, "10.1.0.0/16", cfg)
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("constructing a /16 with %s initial state took %s", tt.want, elapsed)
			}
			stateEntries := len(eng.state)
			pendingEntries := len(eng.pending)
			target := mustIP(t, "10.1.42.99")

			for i := 0; i < 20; i++ {
				state, ok := eng.GetIPState(target)
				if !ok || state.State != tt.want {
					t.Fatalf("read %d state = %#v, %t; want %s, true", i+1, state, ok, tt.want)
				}
			}
			if got := len(eng.state); got != stateEntries {
				t.Fatalf("read-only access changed state entries from %d to %d", stateEntries, got)
			}
			if got := len(eng.pending); got != pendingEntries {
				t.Fatalf("read-only access changed pending entries from %d to %d", pendingEntries, got)
			}
		})
	}
}

func TestPendingInitialStateMaterializesOnARPRequest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InitState = Pending(0)
	cfg.LearnSeconds = 0
	eng, _ := newTestEngineForCIDR(t, "10.1.0.0/24", cfg)
	target := mustIP(t, "10.1.0.99")
	source := mustIP(t, "10.1.0.50")
	sourceMAC := packet.MustParseMAC("00:11:22:33:44:50")

	eng.HandlePacket(packet.Packet{
		SrcMAC:    sourceMAC,
		DstMAC:    packet.MustParseMAC("ff:ff:ff:ff:ff:ff"),
		EtherType: packet.EtherTypeARP,
		ARP: &packet.ARP{
			Opcode:    packet.ARPOpRequest,
			SenderMAC: sourceMAC,
			SenderIP:  source,
			TargetIP:  target,
		},
	})

	eng.mu.Lock()
	state, materialized := eng.state[target]
	_, queued := eng.pending[target]
	eng.mu.Unlock()
	if !materialized || state != Pending(0) || !queued {
		t.Fatalf("ARP request left state=%v materialized=%t pending=%t; want PENDING(0), true, true", state, materialized, queued)
	}
}

func TestInitialStateDoesNotOverrideProtectedAddresses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InitState = Pending(0)
	cfg.LearnSeconds = 0
	cfg.SpongeNet = true

	eng, _ := newTestEngineForCIDR(t, "10.1.0.0/16", cfg)
	for _, tt := range []struct {
		name string
		ip   string
		want string
	}{
		{name: "network", ip: "10.1.0.0", want: "STATIC"},
		{name: "broadcast", ip: "10.1.255.255", want: "STATIC"},
		{name: "own IP", ip: "10.1.0.1", want: "ALIVE"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state, ok := eng.GetIPState(mustIP(t, tt.ip))
			if !ok {
				t.Fatalf("protected address %s has no state", tt.ip)
			}
			if state.State != tt.want {
				t.Fatalf("protected address %s state = %s, want %s", tt.ip, state.State, tt.want)
			}
		})
	}
}

func TestClearAllStateKeepsConfiguredInitialPolicyAndRestoresProtectedAddresses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InitState = Pending(0)
	cfg.LearnSeconds = 0
	cfg.SpongeNet = true

	eng, _ := newTestEngineForCIDR(t, "10.1.0.0/16", cfg)
	target := mustIP(t, "10.1.42.99")
	if state, ok := eng.GetIPState(target); !ok || state.State != "PENDING(0)" {
		t.Fatalf("initial lazy state = %#v, %t; want PENDING(0), true", state, ok)
	}

	eng.ClearAllState()
	stateEntries := len(eng.state)
	pendingEntries := len(eng.pending)
	state, ok := eng.GetIPState(target)
	if !ok || state.State != "PENDING(0)" {
		t.Fatalf("post-clear lazy state = %#v, %t; want PENDING(0), true", state, ok)
	}
	if len(eng.state) != stateEntries || len(eng.pending) != pendingEntries {
		t.Fatal("post-clear read materialized configured initial state")
	}
	for _, tt := range []struct {
		ip   string
		want string
	}{
		{ip: "10.1.0.0", want: "STATIC"},
		{ip: "10.1.255.255", want: "STATIC"},
		{ip: "10.1.0.1", want: "ALIVE"},
	} {
		state, ok := eng.GetIPState(mustIP(t, tt.ip))
		if !ok || state.State != tt.want {
			t.Fatalf("post-clear protected address %s state = %#v, %t; want %s, true", tt.ip, state, ok, tt.want)
		}
	}
}

func TestTickReturnsPromptlyDuringPacedProbeWork(t *testing.T) {
	eng, _ := newTestEngine(t)
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.MaxPending = 10
		cfg.Proberate = 5
		return nil
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	sender := newNotifyingSender(2)
	eng.sender = sender
	for _, ip := range []string{"10.0.0.60", "10.0.0.61"} {
		if err := eng.SetIPState(mustIP(t, ip), Pending(0), packet.MAC{}); err != nil {
			t.Fatalf("set pending %s: %v", ip, err)
		}
	}

	returned := make(chan struct{})
	go func() {
		eng.Tick(time.Now())
		close(returned)
	}()
	select {
	case <-sender.first:
	case <-time.After(time.Second):
		t.Fatal("paced probe work did not start")
	}
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Tick waited for paced probe work")
	}
	select {
	case <-sender.all:
	case <-time.After(time.Second):
		t.Fatal("paced probe work did not finish")
	}
}

func TestStopWaitsForProbePassBeforeSenderClose(t *testing.T) {
	eng, _ := newTestEngine(t)
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.MaxPending = 10
		cfg.Proberate = 5
		return nil
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	sender := newCloseTrackingSender()
	eng.sender = sender
	for _, ip := range []string{"10.0.0.62", "10.0.0.63"} {
		if err := eng.SetIPState(mustIP(t, ip), Pending(0), packet.MAC{}); err != nil {
			t.Fatalf("set pending %s: %v", ip, err)
		}
	}

	eng.Tick(time.Now())
	select {
	case <-sender.first:
	case <-time.After(time.Second):
		t.Fatal("probe pass did not start")
	}
	eng.Stop()
	sender.Close()
	time.Sleep(300 * time.Millisecond)

	if got := sender.AfterClose(); got != 0 {
		t.Fatalf("sender received %d call(s) after engine stop and close", got)
	}
	if got := sender.Count(); got != 1 {
		t.Fatalf("stop allowed %d sends, want only the first in-flight probe", got)
	}
	eng.Tick(time.Now())
	time.Sleep(50 * time.Millisecond)
	if got := sender.AfterClose(); got != 0 {
		t.Fatalf("Tick after Stop sent %d packet(s)", got)
	}
}

func TestOverlappingTicksScheduleOnlyOneProbePass(t *testing.T) {
	eng, _ := newTestEngine(t)
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.MaxPending = 10
		cfg.Proberate = 0
		return nil
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	sender := newGatedSender()
	defer sender.Release()
	eng.sender = sender
	for _, ip := range []string{"10.0.0.70", "10.0.0.71"} {
		if err := eng.SetIPState(mustIP(t, ip), Pending(0), packet.MAC{}); err != nil {
			t.Fatalf("set pending %s: %v", ip, err)
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			eng.Tick(time.Now())
		}()
	}
	close(start)
	select {
	case <-sender.entered:
	case <-time.After(time.Second):
		t.Fatal("probe pass did not reach the sender")
	}

	ticksReturned := make(chan struct{})
	go func() {
		wg.Wait()
		close(ticksReturned)
	}()
	select {
	case <-ticksReturned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("overlapping Tick calls waited for an in-progress pass")
	}

	sender.Release()
	select {
	case <-sender.all:
	case <-time.After(time.Second):
		t.Fatal("single scheduled probe pass did not finish")
	}
	if got := sender.Count(); got != 2 {
		t.Fatalf("overlapping Tick calls sent %d probes, want one pass with 2", got)
	}
}

func TestSweepDoesNotStarvePendingProbes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InitState = StateAlive
	cfg.LearnSeconds = 0
	cfg.SweepPeriod = 60
	cfg.SweepAge = 0
	cfg.Proberate = 2
	cfg.MaxPending = 10
	eng, _ := newTestEngineForCIDR(t, "10.1.0.0/24", cfg)
	defer eng.Stop()

	pendingIP := mustIP(t, "10.1.0.99")
	sender := newSweepPacingSender(pendingIP)
	eng.sender = sender
	eng.SetSweepAtStart()
	eng.Tick(time.Now())
	select {
	case <-sender.sweepStarted:
	case <-time.After(time.Second):
		t.Fatal("sweep did not start")
	}

	if err := eng.SetIPState(pendingIP, Pending(0), packet.MAC{}); err != nil {
		t.Fatalf("set pending: %v", err)
	}
	eng.Tick(time.Now())
	select {
	case <-sender.probeSent:
	case <-time.After(800 * time.Millisecond):
		t.Fatal("in-flight sweep prevented pending probe pass")
	}
	state, ok := eng.GetIPState(pendingIP)
	if !ok || state.State != "PENDING(1)" {
		t.Fatalf("pending state during sweep = %#v, %t; want PENDING(1), true", state, ok)
	}
}

func TestProbeAndSweepShareAggregateProbeRate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InitState = StateNone
	cfg.LearnSeconds = 0
	cfg.SweepPeriod = 60
	cfg.SweepAge = 0
	cfg.Proberate = 20
	eng, _ := newTestEngineForCIDR(t, "10.1.0.0/30", cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sender := newTimedSender()
	eng.sender = sender
	eng.SetSweepAtStart()
	sweepDone := make(chan struct{})
	go func() {
		eng.sweepIfNeeded(ctx, time.Now())
		close(sweepDone)
	}()
	select {
	case <-sender.first:
	case <-time.After(time.Second):
		t.Fatal("sweep did not send its first query")
	}

	pendingIP := mustIP(t, "10.1.0.3")
	if err := eng.SetIPState(pendingIP, Pending(0), packet.MAC{}); err != nil {
		t.Fatalf("set pending: %v", err)
	}
	probeDone := make(chan struct{})
	go func() {
		eng.probePending(ctx, time.Now())
		close(probeDone)
	}()
	select {
	case <-sender.second:
	case <-time.After(time.Second):
		t.Fatal("combined passes did not send a second query")
	}

	times := sender.Times()
	if gap := times[1].Sub(times[0]); gap < 40*time.Millisecond {
		t.Fatalf("combined probe gap = %s, want at least 40ms for a 20 q/s aggregate rate", gap)
	}

	cancel()
	select {
	case <-probeDone:
	case <-time.After(time.Second):
		t.Fatal("pending probe did not stop")
	}
	select {
	case <-sweepDone:
	case <-time.After(time.Second):
		t.Fatal("sweep did not stop")
	}
}

func TestQueryPacerAgesSweepWaiterUnderSustainedPendingBacklog(t *testing.T) {
	var pacer queryPacer
	pacer.configure(10)

	ctx, cancel := context.WithCancel(context.Background())
	if !pacer.wait(ctx, true) {
		t.Fatal("initial pending grant was canceled")
	}

	var workers sync.WaitGroup
	var grantsMu sync.Mutex
	pendingGrants := 0
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for pacer.wait(ctx, true) {
				grantsMu.Lock()
				pendingGrants++
				grantsMu.Unlock()
			}
		}()
	}
	defer func() {
		cancel()
		workers.Wait()
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pacer.mu.Lock()
		waiters := pacer.pendingWaiters
		pacer.mu.Unlock()
		if waiters == 4 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	pacer.mu.Lock()
	waiters := pacer.pendingWaiters
	pacer.mu.Unlock()
	if waiters != 4 {
		t.Fatalf("pending waiters = %d, want 4", waiters)
	}

	started := time.Now()
	sweepGrant := make(chan bool, 1)
	go func() { sweepGrant <- pacer.wait(ctx, false) }()
	select {
	case granted := <-sweepGrant:
		if !granted {
			t.Fatal("aged sweep grant was canceled")
		}
		if elapsed := time.Since(started); elapsed < 10*pacer.interval {
			t.Fatalf("sweep grant after %s, want pending priority before aging", elapsed)
		}
		if elapsed := time.Since(started); elapsed >= 12*pacer.interval {
			t.Fatalf("sweep grant after %s, missed the first eligible shared slot", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sweep waiter made no progress under sustained pending backlog")
	}

	grantsMu.Lock()
	grants := pendingGrants
	grantsMu.Unlock()
	if grants < 8 {
		t.Fatalf("pending grants = %d, want sustained pending work before sweep aging", grants)
	}
}

func TestQueryPacerRestoresPendingPriorityBetweenIndependentlyAgedSweeps(t *testing.T) {
	var pacer queryPacer
	pacer.configure(10)

	ctx, cancel := context.WithCancel(context.Background())
	if !pacer.wait(ctx, true) {
		t.Fatal("initial pending grant was canceled")
	}

	var workers sync.WaitGroup
	var grantsMu sync.Mutex
	pendingGrants := 0
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for pacer.wait(ctx, true) {
				grantsMu.Lock()
				pendingGrants++
				grantsMu.Unlock()
			}
		}()
	}
	defer func() {
		cancel()
		workers.Wait()
	}()
	waitForPacerWaiters(t, &pacer, 4)

	type sweepResult struct {
		started time.Time
		granted time.Time
		ok      bool
	}
	results := make(chan sweepResult, 2)
	for i := 0; i < 2; i++ {
		started := time.Now()
		go func() {
			ok := pacer.wait(ctx, false)
			results <- sweepResult{started: started, granted: time.Now(), ok: ok}
		}()
	}
	waitForSweepWaiters(t, &pacer, 2)

	var first sweepResult
	select {
	case first = <-results:
	case <-time.After(2 * time.Second):
		t.Fatal("first aged sweep waiter did not make progress")
	}
	if !first.ok {
		t.Fatal("first aged sweep waiter was canceled")
	}
	if elapsed := first.granted.Sub(first.started); elapsed < 10*pacer.interval {
		t.Fatalf("first sweep grant after %s, want no grant before ten current intervals", elapsed)
	}

	grantsMu.Lock()
	before := pendingGrants
	grantsMu.Unlock()
	select {
	case second := <-results:
		t.Fatalf("second aged sweep granted after %s before a pending grant", second.granted.Sub(second.started))
	case <-time.After(3 * pacer.interval / 2):
	}
	grantsMu.Lock()
	after := pendingGrants
	grantsMu.Unlock()
	if after <= before {
		t.Fatalf("pending grants = %d after first aged sweep, want a pending grant after %d", after, before)
	}

	var second sweepResult
	select {
	case second = <-results:
	case <-time.After(2 * time.Second):
		t.Fatal("second aged sweep waiter did not make progress after pending priority resumed")
	}
	if !second.ok {
		t.Fatal("second aged sweep waiter was canceled")
	}
}

func TestQueryPacerLaterSweepDoesNotInheritGrantedWaiterAge(t *testing.T) {
	var pacer queryPacer
	pacer.configure(10)

	ctx, cancel := context.WithCancel(context.Background())
	if !pacer.wait(ctx, true) {
		t.Fatal("initial pending grant was canceled")
	}

	var workers sync.WaitGroup
	var grantsMu sync.Mutex
	pendingGrants := 0
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for pacer.wait(ctx, true) {
				grantsMu.Lock()
				pendingGrants++
				grantsMu.Unlock()
			}
		}()
	}
	defer func() {
		cancel()
		workers.Wait()
	}()
	waitForPacerWaiters(t, &pacer, 4)

	type sweepResult struct {
		started time.Time
		granted time.Time
		ok      bool
	}
	results := make(chan sweepResult, 2)
	firstStarted := time.Now()
	go func() {
		ok := pacer.wait(ctx, false)
		results <- sweepResult{started: firstStarted, granted: time.Now(), ok: ok}
	}()
	time.Sleep(2 * pacer.interval)
	secondStarted := time.Now()
	go func() {
		ok := pacer.wait(ctx, false)
		results <- sweepResult{started: secondStarted, granted: time.Now(), ok: ok}
	}()

	var first sweepResult
	select {
	case first = <-results:
	case <-time.After(2 * time.Second):
		t.Fatal("first aged sweep waiter did not make progress")
	}
	if !first.ok {
		t.Fatal("first sweep waiter was canceled")
	}
	if elapsed := first.granted.Sub(first.started); elapsed < 10*pacer.interval {
		t.Fatalf("sweep grant after %s, want no grant before ten current intervals", elapsed)
	}

	grantsMu.Lock()
	before := pendingGrants
	grantsMu.Unlock()
	select {
	case second := <-results:
		t.Fatalf("second sweep grant after %s, want pending priority after one aged grant", second.granted.Sub(second.started))
	case <-time.After(3 * pacer.interval / 2):
	}
	grantsMu.Lock()
	after := pendingGrants
	grantsMu.Unlock()
	if after <= before {
		t.Fatalf("pending grants = %d after aged sweep, want pending priority to resume from %d", after, before)
	}

	var second sweepResult
	select {
	case second = <-results:
	case <-time.After(2 * time.Second):
		t.Fatal("second aged sweep waiter did not make progress")
	}
	if !second.ok {
		t.Fatal("second sweep waiter was canceled")
	}
	if elapsed := second.granted.Sub(second.started); elapsed < 10*pacer.interval {
		t.Fatalf("later sweep grant after %s, inherited the older waiter's age", elapsed)
	}
}

func TestQueryPacerLaterSweepDoesNotInheritCanceledWaiterAge(t *testing.T) {
	var pacer queryPacer
	pacer.configure(10)

	backlogCtx, cancelBacklog := context.WithCancel(context.Background())
	if !pacer.wait(backlogCtx, true) {
		t.Fatal("initial pending grant was canceled")
	}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for pacer.wait(backlogCtx, true) {
			}
		}()
	}
	defer func() {
		cancelBacklog()
		workers.Wait()
	}()
	waitForPacerWaiters(t, &pacer, 4)

	olderCtx, cancelOlder := context.WithCancel(context.Background())
	olderDone := make(chan bool, 1)
	go func() { olderDone <- pacer.wait(olderCtx, false) }()
	time.Sleep(2 * pacer.interval)
	laterStarted := time.Now()
	laterDone := make(chan struct {
		granted time.Time
		ok      bool
	}, 1)
	go func() {
		ok := pacer.wait(backlogCtx, false)
		laterDone <- struct {
			granted time.Time
			ok      bool
		}{granted: time.Now(), ok: ok}
	}()
	cancelOlder()
	select {
	case granted := <-olderDone:
		if granted {
			t.Fatal("canceled older sweep waiter received a grant")
		}
	case <-time.After(time.Second):
		t.Fatal("canceling older sweep waiter did not wake it")
	}

	select {
	case later := <-laterDone:
		if !later.ok {
			t.Fatal("later sweep waiter was canceled")
		}
		if elapsed := later.granted.Sub(laterStarted); elapsed < 10*pacer.interval {
			t.Fatalf("later sweep grant after %s, inherited the canceled waiter's age", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("later sweep waiter did not make progress")
	}
}

func TestQueryPacerTracksEachSweepWaiterAgainstCurrentInterval(t *testing.T) {
	base := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	older := &queryPacerSweepWaiter{since: base}
	later := &queryPacerSweepWaiter{since: base.Add(3 * 10 * time.Second)}
	pacer := queryPacer{
		interval:     20 * time.Second,
		sweepWaiters: []*queryPacerSweepWaiter{older, later},
	}

	if got := pacer.oldestAgedSweepWaiterLocked(base.Add(199 * time.Second)); got != nil {
		t.Fatalf("aged sweep waiter before ten current intervals = %#v, want nil", got)
	}
	if got := pacer.oldestAgedSweepWaiterLocked(base.Add(200 * time.Second)); got != older {
		t.Fatalf("aged sweep waiter at ten current intervals = %#v, want older waiter", got)
	}

	pacer.removeSweepWaiterLocked(older) // Models the forced grant or cancellation.
	if got := pacer.oldestAgedSweepWaiterLocked(base.Add(200 * time.Second)); got != nil {
		t.Fatalf("later waiter inherited older age after removal: %#v", got)
	}
	if got := pacer.oldestAgedSweepWaiterLocked(later.since.Add(199 * time.Second)); got != nil {
		t.Fatalf("later waiter aged before ten current intervals = %#v, want nil", got)
	}
	if got := pacer.oldestAgedSweepWaiterLocked(later.since.Add(200 * time.Second)); got != later {
		t.Fatalf("aged sweep waiter at its ten current intervals = %#v, want later waiter", got)
	}
}

func TestDurableMultiAddressPendingBacklogAllowsSweepToFinish(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InitState = StateNone
	cfg.LearnSeconds = 0
	cfg.MaxPending = 10_000
	cfg.Proberate = 100
	cfg.SweepPeriod = 60
	cfg.SweepAge = 0
	eng, _ := newTestEngineForCIDR(t, "10.1.0.0/29", cfg)

	sweepIP := mustIP(t, "10.1.0.7")
	sender := newTargetCountingSender()
	eng.sender = sender
	pendingIPs := []uint32{
		mustIP(t, "10.1.0.2"),
		mustIP(t, "10.1.0.3"),
		mustIP(t, "10.1.0.4"),
		mustIP(t, "10.1.0.5"),
		mustIP(t, "10.1.0.6"),
	}
	for _, ip := range pendingIPs {
		if err := eng.SetIPState(ip, Pending(0), packet.MAC{}); err != nil {
			t.Fatalf("set pending %s: %v", netutil.IPv4String(ip), err)
		}
	}

	backlogCtx, cancelBacklog := context.WithCancel(context.Background())
	backlogDone := make(chan struct{})
	go func() {
		defer close(backlogDone)
		for {
			select {
			case <-backlogCtx.Done():
				return
			default:
				eng.probePending(backlogCtx, time.Now())
			}
		}
	}()
	defer func() {
		cancelBacklog()
		<-backlogDone
		eng.Stop()
	}()

	waitForPacerPendingWaiter(t, eng)
	eng.SetSweepAtStart()
	eng.startPass(&eng.sweepInProgress, func(ctx context.Context) {
		eng.sweepIfNeeded(ctx, time.Now())
	})
	if !eng.sweepInProgress.Load() {
		t.Fatal("sweep did not start")
	}

	deadline := time.Now().Add(3 * time.Second)
	for eng.sweepInProgress.Load() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if eng.sweepInProgress.Load() {
		t.Fatal("sweep remained in progress under sustained pending work")
	}
	if !sender.WaitForCount(sweepIP, 1, 100*time.Millisecond) {
		t.Fatal("sweep made no measurable progress")
	}
	pendingProbes := 0
	for _, ip := range pendingIPs {
		pendingProbes += sender.Count(ip)
	}
	if pendingProbes < 20 {
		t.Fatalf("pending probes = %d, want a durable multi-address backlog during sweep", pendingProbes)
	}
}

func TestUpdateConfigDisablingProberateWakesExistingWaiter(t *testing.T) {
	eng, _ := newTestEngine(t)
	setTestProberate(t, eng, 1)
	if !eng.waitForProbeRate(context.Background(), false) {
		t.Fatal("initial rate grant was canceled")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- eng.waitForProbeRate(ctx, true) }()
	waitForPacerPendingWaiter(t, eng)

	started := time.Now()
	setTestProberate(t, eng, 0)
	select {
	case granted := <-done:
		if !granted {
			t.Fatal("disabled proberate canceled the existing waiter")
		}
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("disabling proberate woke waiter after %s, want prompt wake", elapsed)
		}
	case <-time.After(150 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("disabling proberate did not wake the existing waiter")
	}
}

func TestUpdateConfigIncreasingProberateReprogramsExistingWaiter(t *testing.T) {
	eng, _ := newTestEngine(t)
	setTestProberate(t, eng, 1)
	if !eng.waitForProbeRate(context.Background(), false) {
		t.Fatal("initial rate grant was canceled")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- eng.waitForProbeRate(ctx, true) }()
	waitForPacerPendingWaiter(t, eng)

	setTestProberate(t, eng, 100)
	select {
	case granted := <-done:
		if !granted {
			t.Fatal("increased proberate canceled the existing waiter")
		}
	case <-time.After(200 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("increased proberate did not reprogram the existing waiter")
	}
}

func TestUpdateConfigLoweringProberateRebasesFromLastGrant(t *testing.T) {
	eng, _ := newTestEngine(t)
	setTestProberate(t, eng, 100)
	if !eng.waitForProbeRate(context.Background(), false) {
		t.Fatal("initial rate grant was canceled")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- eng.waitForProbeRate(ctx, true) }()
	waitForPacerPendingWaiter(t, eng)

	setTestProberate(t, eng, 10)
	select {
	case <-done:
		t.Fatal("lowered proberate granted before the new interval elapsed")
	case <-time.After(60 * time.Millisecond):
	}
	select {
	case granted := <-done:
		if !granted {
			t.Fatal("lowered proberate canceled the existing waiter")
		}
	case <-time.After(250 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("lowered proberate did not reprogram the existing waiter")
	}
}

func setTestProberate(t *testing.T, eng *Engine, rate float64) {
	t.Helper()
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.Proberate = rate
		return nil
	}); err != nil {
		t.Fatalf("update proberate to %g: %v", rate, err)
	}
}

func waitForPacerPendingWaiter(t *testing.T, eng *Engine) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		eng.queryPacer.mu.Lock()
		waiters := eng.queryPacer.pendingWaiters
		eng.queryPacer.mu.Unlock()
		if waiters > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("pacer did not register the pending waiter")
}

func waitForPacerWaiters(t *testing.T, pacer *queryPacer, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pacer.mu.Lock()
		waiters := pacer.pendingWaiters
		pacer.mu.Unlock()
		if waiters >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	pacer.mu.Lock()
	waiters := pacer.pendingWaiters
	pacer.mu.Unlock()
	t.Fatalf("pending waiters = %d, want at least %d", waiters, want)
}

func waitForSweepWaiters(t *testing.T, pacer *queryPacer, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pacer.mu.Lock()
		waiters := len(pacer.sweepWaiters)
		pacer.mu.Unlock()
		if waiters >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	pacer.mu.Lock()
	waiters := len(pacer.sweepWaiters)
	pacer.mu.Unlock()
	t.Fatalf("sweep waiters = %d, want at least %d", waiters, want)
}

func newTestEngineForCIDR(t *testing.T, cidr string, cfg Config) (*Engine, *fakeSender) {
	t.Helper()
	netCIDR, netIP, broadcast, prefixLen, err := netutil.ParseCIDRString(cidr)
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	myIP := mustIP(t, "10.1.0.1")
	mac := packet.MustParseMAC("aa:bb:cc:dd:ee:ff")
	sender := &fakeSender{}
	eng := New(cfg, "eth0", netCIDR, netIP, broadcast, prefixLen, myIP, mac, []uint32{myIP}, sender, nopLogger{})
	return eng, sender
}

type notifyingSender struct {
	mu    sync.Mutex
	sent  int
	want  int
	first chan struct{}
	all   chan struct{}
}

type closeTrackingSender struct {
	mu         sync.Mutex
	closed     bool
	sent       int
	afterClose int
	first      chan struct{}
	once       sync.Once
}

type sweepPacingSender struct {
	pendingIP    uint32
	sweepStarted chan struct{}
	probeSent    chan struct{}
	sweepOnce    sync.Once
	probeOnce    sync.Once
}

type firstTargetSender struct {
	mu    sync.Mutex
	sent  int
	first chan uint32
}

type targetCountingSender struct {
	mu     sync.Mutex
	target map[uint32]int
}

func newTargetCountingSender() *targetCountingSender {
	return &targetCountingSender{target: make(map[uint32]int)}
}

func (s *targetCountingSender) SendARP(arp packet.ARP, _ packet.MAC, _ packet.MAC) error {
	s.mu.Lock()
	s.target[arp.TargetIP]++
	s.mu.Unlock()
	return nil
}

func (s *targetCountingSender) Count(ip uint32) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target[ip]
}

func (s *targetCountingSender) WaitForCount(ip uint32, want int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.Count(ip) >= want {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return s.Count(ip) >= want
}

func newFirstTargetSender() *firstTargetSender {
	return &firstTargetSender{first: make(chan uint32, 1)}
}

func (s *firstTargetSender) SendARP(arp packet.ARP, _ packet.MAC, _ packet.MAC) error {
	s.mu.Lock()
	s.sent++
	sent := s.sent
	s.mu.Unlock()
	if sent == 1 {
		s.first <- arp.TargetIP
	}
	return nil
}

func (s *firstTargetSender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

type timedSender struct {
	mu     sync.Mutex
	times  []time.Time
	first  chan struct{}
	second chan struct{}
}

func newTimedSender() *timedSender {
	return &timedSender{first: make(chan struct{}), second: make(chan struct{})}
}

func (s *timedSender) SendARP(packet.ARP, packet.MAC, packet.MAC) error {
	s.mu.Lock()
	s.times = append(s.times, time.Now())
	count := len(s.times)
	s.mu.Unlock()
	if count == 1 {
		close(s.first)
	}
	if count == 2 {
		close(s.second)
	}
	return nil
}

func (s *timedSender) Times() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.times...)
}

func newSweepPacingSender(pendingIP uint32) *sweepPacingSender {
	return &sweepPacingSender{
		pendingIP:    pendingIP,
		sweepStarted: make(chan struct{}),
		probeSent:    make(chan struct{}),
	}
}

func (s *sweepPacingSender) SendARP(arp packet.ARP, _ packet.MAC, _ packet.MAC) error {
	if arp.TargetIP == s.pendingIP {
		s.probeOnce.Do(func() { close(s.probeSent) })
		return nil
	}
	s.sweepOnce.Do(func() { close(s.sweepStarted) })
	return nil
}

func newCloseTrackingSender() *closeTrackingSender {
	return &closeTrackingSender{first: make(chan struct{})}
}

func (s *closeTrackingSender) SendARP(packet.ARP, packet.MAC, packet.MAC) error {
	s.mu.Lock()
	s.sent++
	if s.closed {
		s.afterClose++
	}
	s.mu.Unlock()
	s.once.Do(func() { close(s.first) })
	return nil
}

func (s *closeTrackingSender) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}

func (s *closeTrackingSender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

func (s *closeTrackingSender) AfterClose() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.afterClose
}

func newNotifyingSender(want int) *notifyingSender {
	return &notifyingSender{want: want, first: make(chan struct{}), all: make(chan struct{})}
}

func (s *notifyingSender) SendARP(packet.ARP, packet.MAC, packet.MAC) error {
	s.mu.Lock()
	s.sent++
	sent := s.sent
	s.mu.Unlock()
	if sent == 1 {
		close(s.first)
	}
	if sent == s.want {
		close(s.all)
	}
	return nil
}

type gatedSender struct {
	mu          sync.Mutex
	sent        int
	first       sync.Once
	releaseOnce sync.Once
	entered     chan struct{}
	release     chan struct{}
	all         chan struct{}
}

type blockingProbeSender struct {
	mu      sync.Mutex
	sent    int
	first   chan uint32
	release chan struct{}
	once    sync.Once
}

func newBlockingProbeSender() *blockingProbeSender {
	return &blockingProbeSender{first: make(chan uint32, 1), release: make(chan struct{})}
}

func (s *blockingProbeSender) SendARP(arp packet.ARP, _ packet.MAC, _ packet.MAC) error {
	s.mu.Lock()
	s.sent++
	sent := s.sent
	s.mu.Unlock()
	if sent == 1 {
		s.first <- arp.TargetIP
		<-s.release
	}
	return nil
}

func (s *blockingProbeSender) Release() {
	s.once.Do(func() { close(s.release) })
}

func (s *blockingProbeSender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

func newGatedSender() *gatedSender {
	return &gatedSender{entered: make(chan struct{}), release: make(chan struct{}), all: make(chan struct{})}
}

func (s *gatedSender) SendARP(packet.ARP, packet.MAC, packet.MAC) error {
	s.first.Do(func() { close(s.entered) })
	<-s.release
	s.mu.Lock()
	s.sent++
	sent := s.sent
	s.mu.Unlock()
	if sent == 2 {
		close(s.all)
	}
	return nil
}

func (s *gatedSender) Release() {
	s.releaseOnce.Do(func() { close(s.release) })
}

func (s *gatedSender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

type recordedLog struct {
	level   LogLevel
	mask    EventMask
	message string
}

type recordingLogger struct {
	entries []recordedLog
}

func (l *recordingLogger) Logf(level LogLevel, mask EventMask, format string, args ...any) {
	l.entries = append(l.entries, recordedLog{level: level, mask: mask, message: fmt.Sprintf(format, args...)})
}

func (l *recordingLogger) containsMessage(substring string) bool {
	for _, entry := range l.entries {
		if strings.Contains(entry.message, substring) {
			return true
		}
	}
	return false
}

func TestSetAliveDoesNotLogClearingWithoutPendingState(t *testing.T) {
	logger := &recordingLogger{}
	eng, _ := newTestEngineWithLogger(t, logger)
	logger.entries = nil
	ip := mustIP(t, "10.0.0.40")
	if err := eng.SetIPState(ip, StateAlive, packet.MustParseMAC("00:11:22:33:44:40")); err != nil {
		t.Fatalf("set alive: %v", err)
	}

	if logger.containsMessage("clearing:") {
		t.Fatal("alive learning emitted a clearing log without a pending state")
	}
}

func TestSetAliveLogsClearingWhenLeavingPendingState(t *testing.T) {
	logger := &recordingLogger{}
	eng, _ := newTestEngineWithLogger(t, logger)
	ip := mustIP(t, "10.0.0.41")
	if err := eng.SetIPState(ip, Pending(0), packet.MAC{}); err != nil {
		t.Fatalf("set pending: %v", err)
	}
	logger.entries = nil
	if err := eng.SetIPState(ip, StateAlive, packet.MustParseMAC("00:11:22:33:44:41")); err != nil {
		t.Fatalf("set alive: %v", err)
	}

	if !logger.containsMessage("clearing:") {
		t.Fatal("pending-to-alive transition did not emit a clearing log")
	}
}

func TestUpdateConfigResetsLearningOnlyWhenDurationChanges(t *testing.T) {
	eng, _ := newTestEngine(t)
	eng.ForceLearning(7)
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.MaxRate = 12.5
		return nil
	}); err != nil {
		t.Fatalf("update unrelated config: %v", err)
	}
	if eng.learningLeft != 7 {
		t.Fatalf("unrelated config update reset learning to %d, want 7", eng.learningLeft)
	}
	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.LearnSeconds = 0
		return nil
	}); err != nil {
		t.Fatalf("update unchanged learning config: %v", err)
	}
	if eng.learningLeft != 7 {
		t.Fatalf("unchanged learning config reset learning to %d, want 7", eng.learningLeft)
	}

	if err := eng.UpdateConfig(func(cfg *Config) error {
		cfg.LearnSeconds = 3
		return nil
	}); err != nil {
		t.Fatalf("update learning config: %v", err)
	}
	if eng.learningLeft != 3 {
		t.Fatalf("learning update left %d seconds, want 3", eng.learningLeft)
	}
}

func TestConcurrentPacketConfigAndLearningUpdates(t *testing.T) {
	eng, _ := newTestEngine(t)
	ipv4 := packet.Packet{
		SrcMAC:    packet.MustParseMAC("00:11:22:33:44:50"),
		DstMAC:    packet.MustParseMAC("00:11:22:33:44:51"),
		EtherType: packet.EtherTypeIPv4,
		IPv4:      &packet.IPv4{SrcIP: mustIP(t, "10.0.0.50"), DstIP: mustIP(t, "10.0.0.51")},
	}
	arp := packet.Packet{
		SrcMAC:    packet.MustParseMAC("00:11:22:33:44:52"),
		DstMAC:    packet.MustParseMAC("ff:ff:ff:ff:ff:ff"),
		EtherType: packet.EtherTypeARP,
		ARP: &packet.ARP{
			Opcode:    packet.ARPOpRequest,
			SenderMAC: packet.MustParseMAC("00:11:22:33:44:52"),
			SenderIP:  mustIP(t, "10.0.0.52"),
			TargetIP:  mustIP(t, "10.0.0.53"),
		},
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			eng.HandlePacket(ipv4)
			eng.HandlePacket(arp)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			flags := UpdateNone
			if i%2 == 0 {
				flags = UpdateReply
			}
			if err := eng.UpdateConfig(func(cfg *Config) error {
				cfg.ArpUpdateFlags = flags
				return nil
			}); err != nil {
				t.Errorf("update config: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for seconds := 0; seconds < 1000; seconds++ {
			eng.ForceLearning(seconds % 2)
		}
	}()
	close(start)
	wg.Wait()
}

func mustIP(t *testing.T, s string) uint32 {
	ip, err := netutil.ParseIPv4String(s)
	if err != nil {
		t.Fatalf("parse ip: %v", err)
	}
	return ip
}

// A blocked announcement must never hold the engine state mutex, and Stop must
// join it before a caller can close the packet sender.
func TestGratuitousTransitionsReleaseStateLockAndJoinShutdown(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		for _, state := range []State{StateDead, StateStatic} {
			if automatic && state == StateStatic {
				continue
			}
			t.Run(fmt.Sprintf("automatic=%v/state=%v", automatic, state), func(t *testing.T) {
				eng, _ := newTestEngine(t)
				eng.cfg.Gratuitous = true
				sender := newBlockingProbeSender()
				eng.sender = sender
				ip := mustIP(t, "10.0.0.88")
				done := make(chan struct{})
				if automatic {
					_ = eng.SetIPState(ip, Pending(eng.cfg.MaxPending), packet.MAC{})
				}
				go func() {
					if automatic {
						eng.Tick(time.Now())
					} else {
						_ = eng.SetIPState(ip, state, packet.MAC{})
					}
					close(done)
				}()
				select {
				case <-sender.first:
				case <-time.After(time.Second):
					t.Fatal("announcement did not reach sender; state transition deadlocked")
				}
				status := make(chan struct{})
				go func() { eng.Status(); close(status) }()
				select {
				case <-status:
				case <-time.After(time.Second):
					t.Fatal("announcement holds state mutex")
				}
				stopped := make(chan struct{})
				go func() { eng.Stop(); close(stopped) }()
				select {
				case <-stopped:
					t.Fatal("Stop returned while announcement was sending")
				case <-time.After(20 * time.Millisecond):
				}
				close(sender.release)
				select {
				case <-stopped:
				case <-time.After(time.Second):
					t.Fatal("Stop did not join announcement")
				}
				<-done
				if sender.Count() != 1 {
					t.Fatalf("got %d announcements, want one", sender.Count())
				}
				got, _ := eng.GetIPState(ip)
				if got.State != state.String() {
					t.Fatalf("got %s, want %s", got.State, state)
				}
			})
		}
	}
}

func TestGratuitousDummyTransitionsComplete(t *testing.T) {
	for _, state := range []State{StateDead, StateStatic} {
		eng, sender := newTestEngine(t)
		eng.cfg.Gratuitous, eng.cfg.Dummy = true, true
		done := make(chan struct{})
		go func() { _ = eng.SetIPState(mustIP(t, "10.0.0.88"), state, packet.MAC{}); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("dummy transition deadlocked")
		}
		if sender.sent != 0 {
			t.Fatal("dummy announcement transmitted")
		}
	}
}

type senderFunc func(packet.ARP, packet.MAC, packet.MAC) error

func (f senderFunc) SendARP(arp packet.ARP, src, dst packet.MAC) error { return f(arp, src, dst) }

func TestGratuitousSendErrorsAreReportedWithoutRollingBackState(t *testing.T) {
	logger := &recordingLogger{}
	eng, _ := newTestEngineWithLogger(t, logger)
	eng.cfg.Gratuitous = true
	eng.sender = senderFunc(func(packet.ARP, packet.MAC, packet.MAC) error { return fmt.Errorf("injection failed") })
	done := make(chan struct{})
	go func() { _ = eng.SetIPState(mustIP(t, "10.0.0.88"), StateDead, packet.MAC{}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("transition blocked")
	}
	got, _ := eng.GetIPState(mustIP(t, "10.0.0.88"))
	if got.State != "DEAD" {
		t.Fatalf("got %s", got.State)
	}
	if !logger.containsMessage("injection failed") {
		t.Fatal("send failure was not reported")
	}
}

func TestFailedPendingProbesDoNotAdvanceState(t *testing.T) {
	logger := &recordingLogger{}
	eng, _ := newTestEngineWithLogger(t, logger)
	eng.cfg.MaxPending = 2
	eng.queryPacer.configure(0)
	ip := mustIP(t, "10.0.0.88")
	_ = eng.SetIPState(ip, Pending(0), packet.MAC{})
	fail := true
	eng.sender = senderFunc(func(packet.ARP, packet.MAC, packet.MAC) error {
		if fail {
			return fmt.Errorf("injection failed")
		}
		return nil
	})
	for n := 0; n < 5; n++ {
		eng.probePending(context.Background(), time.Now())
	}
	got, _ := eng.GetIPState(ip)
	if got.State != "PENDING(0)" {
		t.Fatalf("failed probes advanced state to %s", got.State)
	}
	errors := 0
	for _, entry := range logger.entries {
		if strings.Contains(entry.message, "injection failed") {
			errors++
		}
	}
	if errors != 1 {
		t.Fatalf("send error log count=%d, want one bounded warning", errors)
	}
	for _, step := range []struct {
		fail bool
		want string
	}{{false, "PENDING(1)"}, {true, "PENDING(1)"}, {false, "PENDING(2)"}, {false, "DEAD"}} {
		fail = step.fail
		eng.probePending(context.Background(), time.Now())
		got, _ = eng.GetIPState(ip)
		if got.State != step.want {
			t.Fatalf("fail=%v: got %s, want %s", fail, got.State, step.want)
		}
	}
}

func TestPendingCompletionDoesNotModifyAnotherEpisode(t *testing.T) {
	for _, change := range []string{"alive", "repending", "alive then pending"} {
		t.Run(change, func(t *testing.T) {
			eng, _ := newTestEngine(t)
			eng.queryPacer.configure(0)
			sender := newBlockingProbeSender()
			eng.sender = sender
			ip := mustIP(t, "10.0.0.88")
			_ = eng.SetIPState(ip, Pending(0), packet.MAC{})
			done := make(chan struct{})
			go func() { eng.probePending(context.Background(), time.Now()); close(done) }()
			<-sender.first
			got, _ := eng.GetIPState(ip)
			if got.State != "PENDING(0)" {
				close(sender.release)
				<-done
				t.Fatalf("in-flight probe advanced state to %s", got.State)
			}
			want := "PENDING(0)"
			if change != "repending" {
				_ = eng.SetIPState(ip, StateAlive, packet.MAC{})
				want = "ALIVE"
			}
			if change != "alive" {
				_ = eng.SetIPState(ip, Pending(0), packet.MAC{})
				want = "PENDING(0)"
			}
			close(sender.release)
			<-done
			got, _ = eng.GetIPState(ip)
			if got.State != want {
				t.Fatalf("old send changed new state to %s, want %s", got.State, want)
			}
		})
	}
}

func TestPendingPacingCancellationAndEpisodeReset(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(fmt.Sprintf("reset=%v", reset), func(t *testing.T) {
			eng, sender := newTestEngine(t)
			eng.queryPacer.configure(1)
			eng.waitForProbeRate(context.Background(), true)
			ip := mustIP(t, "10.0.0.88")
			_ = eng.SetIPState(ip, Pending(0), packet.MAC{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { eng.probePending(ctx, time.Now()); close(done) }()
			waitForPendingPacer(t, eng)
			if reset {
				eng.ClearIPState(ip)
				_ = eng.SetIPState(ip, Pending(0), packet.MAC{})
				eng.queryPacer.configure(0)
			} else {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("paced pass did not finish")
			}
			got, _ := eng.GetIPState(ip)
			if got.State != "PENDING(0)" || sender.sent != 0 {
				t.Fatalf("stale/canceled send: state=%s sends=%d", got.State, sender.sent)
			}
		})
	}
}

func waitForPendingPacer(t *testing.T, eng *Engine) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		eng.queryPacer.mu.Lock()
		waiting := eng.queryPacer.pendingWaiters > 0
		eng.queryPacer.mu.Unlock()
		if waiting {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("pending probe did not wait for pacing")
}

func TestPendingClearWhileSendingThenRepending(t *testing.T) {
	eng, _ := newTestEngine(t)
	eng.queryPacer.configure(0)
	sender := newBlockingProbeSender()
	eng.sender = sender
	ip := mustIP(t, "10.0.0.88")
	_ = eng.SetIPState(ip, Pending(0), packet.MAC{})
	done := make(chan struct{})
	go func() { eng.probePending(context.Background(), time.Now()); close(done) }()
	<-sender.first
	cleared := make(chan struct{})
	go func() { eng.ClearIPState(ip); _ = eng.SetIPState(ip, Pending(0), packet.MAC{}); close(cleared) }()
	select {
	case <-cleared:
		t.Fatal("clear passed an active send")
	case <-time.After(20 * time.Millisecond):
	}
	close(sender.release)
	<-cleared
	<-done
	got, _ := eng.GetIPState(ip)
	if got.State != "PENDING(0)" {
		t.Fatalf("old send advanced new episode: %s", got.State)
	}
}

func TestPendingSuppressedModesPreserveSimulation(t *testing.T) {
	for _, dummy := range []bool{false, true} {
		eng, sender := newTestEngine(t)
		eng.cfg.Passive, eng.cfg.Dummy, eng.cfg.MaxPending = !dummy, dummy, 1
		eng.queryPacer.configure(0)
		ip := mustIP(t, "10.0.0.88")
		_ = eng.SetIPState(ip, Pending(0), packet.MAC{})
		eng.probePending(context.Background(), time.Now())
		got, _ := eng.GetIPState(ip)
		if got.State != "PENDING(1)" {
			t.Fatalf("dummy=%v got %s", dummy, got.State)
		}
		eng.probePending(context.Background(), time.Now())
		got, _ = eng.GetIPState(ip)
		if got.State != "DEAD" || sender.sent != 0 {
			t.Fatalf("dummy=%v state=%s sends=%d", dummy, got.State, sender.sent)
		}
	}
}

func TestFailedSweepDoesNotCountOrPostponeTarget(t *testing.T) {
	logger := &recordingLogger{}
	eng, _ := newTestEngineWithLogger(t, logger)
	ip := mustIP(t, "10.0.0.88")
	eng.netLo, eng.netHi = ip, ip
	eng.cfg.SweepPeriod = 1
	eng.queryPacer.configure(0)
	eng.nextSweep = time.Unix(1, 0)
	eng.stateMtime[ip] = 1
	eng.sender = senderFunc(func(packet.ARP, packet.MAC, packet.MAC) error { return fmt.Errorf("sweep injection failed") })
	eng.sweepIfNeeded(context.Background(), time.Now())
	if eng.stateMtime[ip] != 1 {
		t.Fatal("failed sweep postponed target")
	}
	if logger.containsMessage("queried 1 IP") {
		t.Fatal("failed sweep counted as queried")
	}
	if !logger.containsMessage("sweep injection failed") {
		t.Fatal("failed sweep not reported")
	}
}

func TestAutomaticGratuitousDummyTransition(t *testing.T) {
	eng, sender := newTestEngine(t)
	eng.cfg.Gratuitous, eng.cfg.Dummy = true, true
	ip := mustIP(t, "10.0.0.88")
	_ = eng.SetIPState(ip, Pending(eng.cfg.MaxPending), packet.MAC{})
	eng.probePending(context.Background(), time.Now())
	got, _ := eng.GetIPState(ip)
	if got.State != "DEAD" || sender.sent != 0 {
		t.Fatalf("state=%s announcements=%d", got.State, sender.sent)
	}
}

func TestPendingSendOutcomes(t *testing.T) {
	for _, tt := range []struct {
		name string
		want probeResult
	}{{"sent", probeSent}, {"dummy", probeSuppressed}, {"passive", probeSuppressed}, {"failed", probeFailed}, {"cleared", probeSkipped}} {
		t.Run(tt.name, func(t *testing.T) {
			eng, _ := newTestEngine(t)
			ip := mustIP(t, "10.0.0.88")
			_ = eng.SetIPState(ip, Pending(0), packet.MAC{})
			episode := eng.pending[ip]
			switch tt.name {
			case "dummy":
				eng.cfg.Dummy = true
			case "passive":
				eng.cfg.Passive = true
			case "failed":
				eng.sender = nil
			case "cleared":
				eng.ClearIPState(ip)
			}
			if got := eng.sendPendingProbe(context.Background(), ip, episode, false); got != tt.want {
				t.Fatalf("result=%v want %v", got, tt.want)
			}
		})
	}
}

func TestDummySweepCountsSimulatedQuery(t *testing.T) {
	logger := &recordingLogger{}
	eng, sender := newTestEngineWithLogger(t, logger)
	ip := mustIP(t, "10.0.0.88")
	eng.netLo, eng.netHi = ip, ip
	eng.cfg.SweepPeriod, eng.cfg.Dummy = 1, true
	eng.queryPacer.configure(0)
	eng.nextSweep = time.Unix(1, 0)
	eng.stateMtime[ip] = 1
	eng.sweepIfNeeded(context.Background(), time.Now())
	if eng.stateMtime[ip] <= 1 || !logger.containsMessage("queried 1 IP") || sender.sent != 0 {
		t.Fatal("dummy sweep did not count exactly one simulated query")
	}
}

// Done is first consulted after the pending pass snapshots its configuration.
// Switching modes at that boundary deterministically exercises an update that
// races with a passive attempt, without depending on scheduler timing.
type configurationSwitchContext struct {
	context.Context
	once         sync.Once
	switchConfig func()
}

func (c *configurationSwitchContext) Done() <-chan struct{} {
	c.once.Do(c.switchConfig)
	return c.Context.Done()
}

func TestPassiveSnapshotCannotTransmitAfterActiveUpdateWithoutPacing(t *testing.T) {
	eng, sender := newTestEngine(t)
	if err := eng.UpdateConfig(func(cfg *Config) error { cfg.Passive = true; cfg.Proberate = 1; return nil }); err != nil {
		t.Fatal(err)
	}
	ip := mustIP(t, "10.0.0.88")
	if err := eng.SetIPState(ip, Pending(0), packet.MAC{}); err != nil {
		t.Fatal(err)
	}
	ctx := &configurationSwitchContext{Context: context.Background(), switchConfig: func() {
		if err := eng.UpdateConfig(func(cfg *Config) error { cfg.Passive = false; return nil }); err != nil {
			t.Fatal(err)
		}
	}}
	eng.probePending(ctx, time.Now())
	if sender.sent != 0 {
		t.Fatalf("passive attempt transmitted %d queries after active update without pacing", sender.sent)
	}
	state, _ := eng.GetIPState(ip)
	if state.State != "PENDING(1)" {
		t.Fatalf("passive cycle did not simulate progress: %s", state.State)
	}
	if !eng.queryPacer.lastGrant.IsZero() {
		t.Fatal("passive simulation unexpectedly consumed a pacing permit")
	}
	eng.probePending(context.Background(), time.Now())
	if sender.sent != 1 || eng.queryPacer.lastGrant.IsZero() {
		t.Fatal("next active attempt did not transmit with a pacing permit")
	}
}
