package engine

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"arpsponge/internal/netutil"
	"arpsponge/internal/packet"
)

var ErrNoSender = errors.New("no packet sender available")

// Logger is a minimal logger used by the engine.
type Logger interface {
	Logf(level LogLevel, event EventMask, format string, args ...any)
}

type Sender interface {
	SendARP(arp packet.ARP, srcMAC packet.MAC, dstMAC packet.MAC) error
}

type Config struct {
	QueueDepth      int
	MaxRate         float64
	ArpAge          int
	MaxPending      int
	Proberate       float64
	FloodProtection float64
	InitState       State
	LearnSeconds    int
	LogLevel        LogLevel
	LogMask         EventMask
	Dummy           bool
	Passive         bool
	Static          bool
	Gratuitous      bool
	SpongeNet       bool
	SweepPeriod     int
	SweepAge        int
	SweepSkipAlive  bool
	ArpUpdateFlags  UpdateFlags
}

func DefaultConfig() Config {
	return Config{
		QueueDepth:      1000,
		MaxRate:         50.0,
		ArpAge:          600,
		MaxPending:      5,
		Proberate:       100,
		FloodProtection: 3.0,
		InitState:       StateAlive,
		LearnSeconds:    5,
		LogLevel:        LevelInfo,
		LogMask:         EventAll,
		Dummy:           false,
		Passive:         false,
		Static:          false,
		Gratuitous:      false,
		SpongeNet:       false,
		SweepPeriod:     0,
		SweepAge:        0,
		SweepSkipAlive:  false,
		ArpUpdateFlags:  UpdateNone,
	}
}

type ArpEntry struct {
	MAC  packet.MAC
	Time int64
}

type Engine struct {
	mu sync.Mutex

	cfg Config

	device    string
	network   *net.IPNet
	prefixLen int
	netIP     uint32
	broadcast uint32
	myIP      uint32
	myMAC     packet.MAC
	myIPs     map[uint32]struct{}

	netLo uint32
	netHi uint32

	queue *Queue

	state      map[uint32]State
	stateAtime map[uint32]int64
	stateMtime map[uint32]int64
	arpTable   map[uint32]ArpEntry
	pending    map[uint32]struct{}

	logger Logger
	sender Sender

	startTime     time.Time
	learningLeft  int
	nextSweep     time.Time
	forcedPassive bool

	lastStaticWarn time.Time
	lastStaticMsg  string
	staticWarns    int
}

func New(cfg Config, device string, network *net.IPNet, netIP uint32, broadcast uint32, prefixLen int, myIP uint32, myMAC packet.MAC, ownIPs []uint32, sender Sender, logger Logger) *Engine {
	if cfg.QueueDepth <= 0 {
		cfg.QueueDepth = 1
	}
	ownSet := make(map[uint32]struct{})
	for _, ip := range ownIPs {
		ownSet[ip] = struct{}{}
	}
	ownSet[myIP] = struct{}{}
	e := &Engine{
		cfg:        cfg,
		device:     device,
		network:    network,
		prefixLen:  prefixLen,
		netIP:      netIP,
		broadcast:  broadcast,
		myIP:       myIP,
		myMAC:      myMAC,
		myIPs:      ownSet,
		netLo:      netIP,
		netHi:      broadcast,
		queue:      NewQueue(cfg.QueueDepth),
		state:      make(map[uint32]State),
		stateAtime: make(map[uint32]int64),
		stateMtime: make(map[uint32]int64),
		arpTable:   make(map[uint32]ArpEntry),
		pending:    make(map[uint32]struct{}),
		logger:     logger,
		sender:     sender,
		startTime:  time.Now(),
	}
	e.learningLeft = cfg.LearnSeconds
	if cfg.SweepPeriod > 0 {
		e.nextSweep = time.Now().Add(time.Duration(cfg.SweepPeriod) * time.Second)
	}
	if cfg.SpongeNet {
		e.setStateLocked(netIP, StateStatic, time.Now().Unix())
		e.setStateLocked(broadcast, StateStatic, time.Now().Unix())
	}
	if myIP == 0 && !cfg.Passive {
		e.forcedPassive = true
		e.cfg.Passive = true
	}
	e.initAllStateLocked(cfg.InitState)
	return e
}

func (e *Engine) Device() string {
	return e.device
}

func (e *Engine) NetworkString() string {
	if e.network == nil {
		return ""
	}
	return e.network.String()
}

func (e *Engine) PrefixLen() int {
	return e.prefixLen
}

func (e *Engine) MyIP() uint32 {
	return e.myIP
}

func (e *Engine) MyMAC() packet.MAC {
	return e.myMAC
}

func (e *Engine) Config() Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

func (e *Engine) UpdateConfig(update func(cfg *Config) error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	cfg := e.cfg
	if err := update(&cfg); err != nil {
		return err
	}
	if cfg.QueueDepth <= 0 {
		return fmt.Errorf("queue_depth must be > 0")
	}
	if cfg.Proberate < 0 {
		return fmt.Errorf("proberate must be >= 0")
	}
	if e.forcedPassive {
		cfg.Passive = true
	}
	e.cfg = cfg
	e.queue.SetMaxDepth(cfg.QueueDepth)
	if cfg.SweepPeriod <= 0 {
		e.nextSweep = time.Time{}
	} else if e.nextSweep.IsZero() {
		e.nextSweep = time.Now().Add(time.Duration(cfg.SweepPeriod) * time.Second)
	}
	return nil
}

func (e *Engine) initAllStateLocked(state State) {
	if state != StateNone {
		for ip := e.netLo; ; ip++ {
			e.setStateLocked(ip, state, 0)
			if ip == e.netHi {
				break
			}
		}
	}
	for ip := range e.myIPs {
		e.setAliveLocked(ip, e.myMAC)
	}
}

func (e *Engine) setStateLocked(ip uint32, state State, now int64) {
	if state >= 0 {
		e.pending[ip] = struct{}{}
	} else {
		delete(e.pending, ip)
	}
	e.state[ip] = state
	e.stateMtime[ip] = now
	e.stateAtime[ip] = now
}

func (e *Engine) clearStateLocked(ip uint32) {
	delete(e.state, ip)
	delete(e.stateAtime, ip)
	delete(e.stateMtime, ip)
	delete(e.pending, ip)
	e.queue.Clear(ip)
}

func (e *Engine) getStateLocked(ip uint32) (State, bool) {
	state, ok := e.state[ip]
	return state, ok
}

func (e *Engine) setStateAtimeLocked(ip uint32, now int64) {
	e.stateAtime[ip] = now
}

func (e *Engine) setStateMtimeLocked(ip uint32, now int64) {
	e.stateMtime[ip] = now
}

func (e *Engine) setPendingLocked(ip uint32, n int) {
	e.setStateLocked(ip, Pending(n), time.Now().Unix())
	e.logf(LevelNotice, EventSponge, "pending: ip=%s state=%d", netutil.IPv4String(ip), n)
}

func (e *Engine) incrPendingLocked(ip uint32) {
	state := e.state[ip]
	pending := int(state)
	e.setPendingLocked(ip, pending+1)
}

func (e *Engine) setDeadLocked(ip uint32) {
	rate := e.queue.Rate(ip)
	e.logf(LevelNotice, EventSponge, "sponging: ip=%s rate=%.1f", netutil.IPv4String(ip), rate)
	if e.cfg.Gratuitous {
		e.gratuitousARP(ip)
	}
	e.setStateLocked(ip, StateDead, time.Now().Unix())
}

func (e *Engine) setStaticLocked(ip uint32) {
	rate := e.queue.Rate(ip)
	e.logf(LevelNotice, EventSponge, "static sponging: ip=%s rate=%.1f", netutil.IPv4String(ip), rate)
	if e.cfg.Gratuitous {
		e.gratuitousARP(ip)
	}
	e.setStateLocked(ip, StateStatic, time.Now().Unix())
}

func (e *Engine) setAliveLocked(ip uint32, mac packet.MAC) {
	if !e.isMyNetwork(ip) {
		return
	}
	oldState, _ := e.getStateLocked(ip)
	oldEntry, hasOld := e.arpTable[ip]
	if mac.IsZero() && hasOld {
		mac = oldEntry.MAC
	}
	if mac.IsZero() {
		mac = packet.MAC{}
	}
	if !hasOld {
		e.logf(LevelDebug, EventState, "learned: ip=%s mac=%s old=none", netutil.IPv4String(ip), mac.String())
	} else if oldEntry.MAC != mac {
		e.logf(LevelDebug, EventState, "learned: ip=%s mac=%s old=%s", netutil.IPv4String(ip), mac.String(), oldEntry.MAC.String())
	}
	if !mac.IsZero() {
		e.logf(LevelDebug, EventState, "clearing: ip=%s mac=%s", netutil.IPv4String(ip), mac.String())
	}
	e.queue.Clear(ip)
	e.setStateLocked(ip, StateAlive, time.Now().Unix())
	if !mac.IsZero() {
		e.arpTable[ip] = ArpEntry{MAC: mac, Time: time.Now().Unix()}
	}
	if oldState == StateDead {
		e.logf(LevelNotice, EventSponge, "unsponging: ip=%s mac=%s", netutil.IPv4String(ip), mac.String())
		return
	}
	if oldState >= 0 {
		e.logf(LevelNotice, EventSponge, "clearing: ip=%s mac=%s", netutil.IPv4String(ip), mac.String())
		return
	}
}

func (e *Engine) isMyNetwork(ip uint32) bool {
	return netutil.InNet(ip, e.netIP, e.prefixLen)
}

func (e *Engine) isMyIP(ip uint32) bool {
	_, ok := e.myIPs[ip]
	return ok
}

func (e *Engine) logf(level LogLevel, event EventMask, format string, args ...any) {
	if e.logger == nil {
		return
	}
	e.logger.Logf(level, event, format, args...)
}

func (e *Engine) HandlePacket(pkt packet.Packet) {
	if pkt.SrcMAC == e.myMAC {
		return
	}

	switch pkt.EtherType {
	case packet.EtherTypeIPv4:
		if pkt.IPv4 == nil {
			return
		}
		e.handleIPv4(pkt)
	case packet.EtherTypeARP:
		if pkt.ARP == nil {
			return
		}
		e.handleARP(pkt)
	}
}

func (e *Engine) handleIPv4(pkt packet.Packet) {
	srcIP := pkt.IPv4.SrcIP
	if !e.isMyNetwork(srcIP) {
		return
	}
	e.updateStateFromTraffic(srcIP, pkt.SrcMAC)

	if e.cfg.ArpUpdateFlags == UpdateNone {
		return
	}
	if pkt.DstMAC != e.myMAC {
		return
	}
	dstIP := pkt.IPv4.DstIP
	if e.isMyNetwork(dstIP) && !e.isMyIP(dstIP) {
		e.mu.Lock()
		state := e.state[dstIP]
		entry, ok := e.arpTable[dstIP]
		e.mu.Unlock()
		if state == StateAlive && ok && !entry.MAC.IsZero() {
			_ = e.sendARPUpdate(pkt.SrcMAC, srcIP, entry.MAC, dstIP)
		}
	}
}

func (e *Engine) updateStateFromTraffic(srcIP uint32, srcMAC packet.MAC) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, ok := e.state[srcIP]
	if !ok {
		state = StateAlive
	}
	if e.cfg.Static && state < StateAlive {
		err := fmt.Sprintf("traffic from STATIC sponged IP: src.mac=%s src.ip=%s", srcMAC.String(), netutil.IPv4String(srcIP))
		e.logStaticWarn(err)
		e.arpTable[srcIP] = ArpEntry{MAC: srcMAC, Time: time.Now().Unix()}
		return
	}
	e.setAliveLocked(srcIP, srcMAC)
}

func (e *Engine) logStaticWarn(msg string) {
	if msg != e.lastStaticMsg {
		if e.staticWarns > 1 {
			e.logf(LevelWarning, EventStatic, "previous STATIC warning repeated %d time(s): %s", e.staticWarns-1, e.lastStaticMsg)
		}
		e.logf(LevelWarning, EventStatic, "%s", msg)
		e.staticWarns = 0
		e.lastStaticMsg = msg
		e.lastStaticWarn = time.Now()
		return
	}
	e.staticWarns++
	if e.staticWarns > 1 && time.Since(e.lastStaticWarn) > 15*time.Second {
		e.logf(LevelWarning, EventStatic, "previous STATIC warning repeated %d time(s): %s", e.staticWarns-1, e.lastStaticMsg)
		e.staticWarns = 0
		e.lastStaticWarn = time.Now()
	}
}

func (e *Engine) handleARP(pkt packet.Packet) {
	arp := pkt.ARP
	srcIP := arp.SenderIP
	dstIP := arp.TargetIP

	e.updateStateFromTraffic(srcIP, pkt.SrcMAC)

	if arp.Opcode != packet.ARPOpRequest {
		return
	}

	if arp.SenderMAC != pkt.SrcMAC {
		e.logf(LevelWarning, EventSpoof,
			"ARP spoofing: src.mac=%s arp.sha=%s arp.spa=%s arp.tpa=%s dst.mac=%s",
			pkt.SrcMAC.String(), arp.SenderMAC.String(), netutil.IPv4String(srcIP), netutil.IPv4String(dstIP), pkt.DstMAC.String(),
		)
	}

	if !e.isMyNetwork(dstIP) {
		e.logf(LevelWarning, EventAlien,
			"misplaced ARP: src.mac=%s arp.spa=%s arp.tpa=%s",
			pkt.SrcMAC.String(), netutil.IPv4String(srcIP), netutil.IPv4String(dstIP),
		)
		return
	}

	if e.isMyIP(dstIP) {
		e.mu.Lock()
		e.setAliveLocked(dstIP, e.myMAC)
		e.mu.Unlock()
		return
	}

	if srcIP == 0 {
		e.logf(LevelNotice, EventSponge,
			"DHCP duplicate IP detection: src.mac=%s arp.tpa=%s",
			pkt.SrcMAC.String(), netutil.IPv4String(dstIP),
		)
		e.mu.Lock()
		state, ok := e.getStateLocked(dstIP)
		if ok && state != StateAlive && !e.cfg.Static {
			e.setPendingLocked(dstIP, 0)
		}
		e.mu.Unlock()
		return
	}

	if dstIP == e.netIP {
		e.logf(LevelWarning, EventAlien,
			"ARP for network address: src.mac=%s arp.spa=%s arp.tpa=%s",
			pkt.SrcMAC.String(), netutil.IPv4String(srcIP), netutil.IPv4String(dstIP),
		)
		if e.cfg.SpongeNet {
			_ = e.sendReply(dstIP, arp)
		}
		return
	}

	if dstIP == e.broadcast {
		e.logf(LevelWarning, EventAlien,
			"ARP for broadcast address: src.mac=%s arp.spa=%s arp.tpa=%s",
			pkt.SrcMAC.String(), netutil.IPv4String(srcIP), netutil.IPv4String(dstIP),
		)
		if e.cfg.SpongeNet {
			_ = e.sendReply(dstIP, arp)
		}
		return
	}

	if e.learningLeft > 0 {
		return
	}

	now := time.Now()
	e.mu.Lock()
	e.queue.Add(dstIP, srcIP, now)
	state, ok := e.getStateLocked(dstIP)
	if !ok {
		if !e.cfg.Static {
			e.setPendingLocked(dstIP, 0)
		}
		e.mu.Unlock()
		return
	}
	if state <= StateDead {
		e.mu.Unlock()
		_ = e.sendReply(dstIP, arp)
		return
	}
	if state != StateAlive {
		e.mu.Unlock()
		return
	}
	if !e.queue.IsFull(dstIP) || e.queue.Rate(dstIP) <= e.cfg.MaxRate {
		e.mu.Unlock()
		return
	}
	if e.cfg.FloodProtection <= 0 {
		if !e.cfg.Static {
			e.setPendingLocked(dstIP, 0)
		}
		e.mu.Unlock()
		return
	}
	d1 := e.queue.Depth(dstIP)
	r1 := e.queue.Rate(dstIP)
	d2 := e.queue.Reduce(dstIP, e.cfg.FloodProtection)
	r2 := e.queue.Rate(dstIP)
	e.mu.Unlock()

	if d1 != d2 {
		e.logf(LevelNotice, EventSponge,
			"%s queue reduced: [depth,rate] = [%d,%.1f] -> [%d,%.1f]",
			netutil.IPv4String(dstIP), d1, r1, d2, r2,
		)
	} else {
		e.logf(LevelNotice, EventSponge,
			"%s queue reduction had no effect: [depth,rate] = [%d,%.1f]",
			netutil.IPv4String(dstIP), d1, r1,
		)
	}

	e.mu.Lock()
	if e.queue.IsFull(dstIP) && e.queue.Rate(dstIP) > e.cfg.MaxRate {
		if !e.cfg.Static {
			e.setPendingLocked(dstIP, 0)
		}
	}
	e.mu.Unlock()
}

func (e *Engine) Tick(now time.Time) {
	e.mu.Lock()
	if e.learningLeft > 0 {
		e.learningLeft--
		left := e.learningLeft
		e.mu.Unlock()
		if left == 0 {
			e.logf(LevelNotice, EventState, "exiting learning state")
		}
		return
	}
	e.mu.Unlock()

	e.probePending(now)
	e.sweepIfNeeded(now)
}

func (e *Engine) probePending(now time.Time) {
	e.mu.Lock()
	if e.forcedPassive {
		e.mu.Unlock()
		e.logf(LevelWarning, EventState, "%s has no IP address; forced --passive; pending addresses not queried", e.device)
		return
	}
	pending := make([]uint32, 0, len(e.pending))
	for ip := range e.pending {
		pending = append(pending, ip)
	}
	proberate := e.cfg.Proberate
	maxPending := e.cfg.MaxPending
	passive := e.cfg.Passive
	staticMode := e.cfg.Static
	e.mu.Unlock()

	if len(pending) == 0 {
		return
	}

	sleep := time.Duration(0)
	if proberate > 0 {
		sleep = time.Duration(float64(time.Second) / proberate)
	}

	processed := 0
	for _, ip := range pending {
		processed++
		e.mu.Lock()
		state := e.state[ip]
		pendingCount := int(state)
		if pendingCount > maxPending {
			e.setDeadLocked(ip)
			e.mu.Unlock()
			continue
		}
		if staticMode {
			e.mu.Unlock()
			continue
		}
		e.incrPendingLocked(ip)
		e.mu.Unlock()

		if !passive {
			_ = e.sendQuery(ip)
		}
		if sleep > 0 {
			time.Sleep(sleep)
		}
	}
	if processed > 1 {
		e.logf(LevelNotice, EventState, "%d pending address(es) processed", processed)
	}
}

func (e *Engine) sweepIfNeeded(now time.Time) {
	e.mu.Lock()
	if e.cfg.SweepPeriod <= 0 || e.nextSweep.IsZero() || now.Before(e.nextSweep) {
		e.mu.Unlock()
		return
	}
	sweepAge := e.cfg.SweepAge
	proberate := e.cfg.Proberate
	passive := e.cfg.Passive
	staticMode := e.cfg.Static
	skipAlive := e.cfg.SweepSkipAlive
	e.nextSweep = now.Add(time.Duration(e.cfg.SweepPeriod) * time.Second)
	e.mu.Unlock()

	if e.forcedPassive || passive || staticMode {
		if e.forcedPassive {
			e.logf(LevelWarning, EventState, "%s has no IP address; forced --passive; IP sweeping disabled", e.device)
		}
		return
	}

	e.logf(LevelNotice, EventState, "sweeping for quiet entries on %s/%d", netutil.IPv4String(e.netIP), e.prefixLen)

	sleep := time.Duration(0)
	if proberate > 0 {
		sleep = time.Duration(float64(time.Second) / proberate)
	}

	queried := 0
	for ip := e.netLo; ; ip++ {
		e.mu.Lock()
		state, ok := e.getStateLocked(ip)
		mtime := e.stateMtime[ip]
		entry, hasEntry := e.arpTable[ip]
		e.mu.Unlock()

		age := int(now.Unix() - mtime)
		doQuery := false
		if !ok {
			if age >= sweepAge {
				doQuery = true
			}
		} else if state == StateAlive {
			if age >= sweepAge {
				if !skipAlive || entry.MAC.IsZero() || !hasEntry {
					doQuery = true
				}
			}
		} else if age >= sweepAge {
			doQuery = true
		}

		if doQuery {
			_ = e.sendQuery(ip)
			e.mu.Lock()
			e.setStateMtimeLocked(ip, time.Now().Unix())
			e.mu.Unlock()
			queried++
			if sleep > 0 {
				time.Sleep(sleep)
			}
		}
		if ip == e.netHi {
			break
		}
	}
	if queried > 0 {
		e.logf(LevelNotice, EventState, "queried %d IP address(es)", queried)
	}
}

func (e *Engine) sendQuery(ip uint32) error {
	e.mu.Lock()
	e.setStateAtimeLocked(ip, time.Now().Unix())
	passive := e.cfg.Passive
	dummy := e.cfg.Dummy
	e.mu.Unlock()
	if passive {
		return nil
	}
	if dummy {
		e.logf(LevelDebug, EventState, "[DUMMY] Querying [dev=%s]: %s", e.device, netutil.IPv4String(ip))
		return nil
	}
	if e.sender == nil {
		return ErrNoSender
	}
	arp := packet.ARP{
		Opcode:    packet.ARPOpRequest,
		SenderMAC: e.myMAC,
		SenderIP:  e.myIP,
		TargetMAC: packet.MAC{},
		TargetIP:  ip,
	}
	return e.sender.SendARP(arp, e.myMAC, packet.MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
}

func (e *Engine) sendReply(srcIP uint32, req *packet.ARP) error {
	e.mu.Lock()
	e.setStateAtimeLocked(srcIP, time.Now().Unix())
	dummy := e.cfg.Dummy
	e.mu.Unlock()

	if dummy {
		e.logf(LevelNotice, EventSponge, "%s: DUMMY sponge reply to %s@%s", netutil.IPv4String(srcIP), netutil.IPv4String(req.SenderIP), req.SenderMAC.String())
		return nil
	}
	if e.sender == nil {
		return ErrNoSender
	}
	arp := packet.ARP{
		Opcode:    packet.ARPOpReply,
		SenderMAC: e.myMAC,
		SenderIP:  srcIP,
		TargetMAC: req.SenderMAC,
		TargetIP:  req.SenderIP,
	}
	return e.sender.SendARP(arp, e.myMAC, req.SenderMAC)
}

func (e *Engine) sendARPUpdate(dstMAC packet.MAC, dstIP uint32, srcMAC packet.MAC, srcIP uint32) error {
	e.mu.Lock()
	flags := e.cfg.ArpUpdateFlags
	dummy := e.cfg.Dummy
	e.mu.Unlock()
	if dummy || e.sender == nil {
		return nil
	}
	if flags&UpdateReply != 0 {
		arp := packet.ARP{Opcode: packet.ARPOpReply, SenderMAC: srcMAC, SenderIP: srcIP, TargetMAC: dstMAC, TargetIP: dstIP}
		_ = e.sender.SendARP(arp, srcMAC, dstMAC)
	}
	if flags&UpdateRequest != 0 {
		arp := packet.ARP{Opcode: packet.ARPOpRequest, SenderMAC: srcMAC, SenderIP: srcIP, TargetMAC: dstMAC, TargetIP: dstIP}
		_ = e.sender.SendARP(arp, srcMAC, dstMAC)
	}
	if flags&UpdateGratuitous != 0 {
		arp := packet.ARP{Opcode: packet.ARPOpRequest, SenderMAC: srcMAC, SenderIP: srcIP, TargetMAC: dstMAC, TargetIP: srcIP}
		_ = e.sender.SendARP(arp, srcMAC, dstMAC)
	}
	return nil
}

func (e *Engine) gratuitousARP(ip uint32) {
	e.mu.Lock()
	dummy := e.cfg.Dummy
	e.mu.Unlock()
	if dummy || e.sender == nil {
		return
	}
	arp := packet.ARP{Opcode: packet.ARPOpRequest, SenderMAC: e.myMAC, SenderIP: ip, TargetMAC: packet.MAC{}, TargetIP: ip}
	_ = e.sender.SendARP(arp, e.myMAC, packet.MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	nextSweep := int64(0)
	if !e.nextSweep.IsZero() {
		nextSweep = int64(time.Until(e.nextSweep).Seconds())
	}
	return Status{
		ID:             "arpsponge",
		PID:            os.Getpid(),
		Version:        Version,
		Date:           time.Now().Unix(),
		Started:        e.startTime.Unix(),
		Network:        netutil.IPv4String(e.netIP),
		PrefixLen:      e.prefixLen,
		Interface:      e.device,
		IP:             netutil.IPv4String(e.myIP),
		MAC:            e.myMAC.String(),
		QueueDepth:     e.cfg.QueueDepth,
		MaxRate:        e.cfg.MaxRate,
		FloodProtect:   e.cfg.FloodProtection,
		MaxPending:     e.cfg.MaxPending,
		SweepPeriod:    e.cfg.SweepPeriod,
		SweepAge:       e.cfg.SweepAge,
		SweepSkipAlive: e.cfg.SweepSkipAlive,
		Proberate:      e.cfg.Proberate,
		NextSweep:      nextSweep,
		LearningLeft:   e.learningLeft,
		Dummy:          e.cfg.Dummy,
		Passive:        e.cfg.Passive,
		Static:         e.cfg.Static,
		SpongeNet:      e.cfg.SpongeNet,
	}
}

func (e *Engine) SnapshotState() []IPState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]IPState, 0, len(e.state))
	for ip, state := range e.state {
		depth := e.queue.Depth(ip)
		rate := e.queue.Rate(ip)
		out = append(out, IPState{
			IP:         netutil.IPv4String(ip),
			State:      state.String(),
			Queue:      depth,
			Rate:       rate,
			StateMTime: e.stateMtime[ip],
			StateATime: e.stateAtime[ip],
		})
	}
	return out
}

func (e *Engine) SnapshotARP() []ARPState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ARPState, 0, len(e.arpTable))
	for ip, entry := range e.arpTable {
		out = append(out, ARPState{
			IP:   netutil.IPv4String(ip),
			MAC:  entry.MAC.String(),
			Time: entry.Time,
		})
	}
	return out
}

func (e *Engine) SetIPState(ip uint32, state State, mac packet.MAC) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if state == StateAlive {
		e.setAliveLocked(ip, mac)
		return nil
	}
	if state == StateDead {
		e.setDeadLocked(ip)
		return nil
	}
	if state == StateStatic {
		e.setStaticLocked(ip)
		return nil
	}
	if state >= 0 {
		e.setPendingLocked(ip, int(state))
		return nil
	}
	return fmt.Errorf("invalid state")
}

func (e *Engine) ClearIPState(ip uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clearStateLocked(ip)
}

func (e *Engine) ClearAllState() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = make(map[uint32]State)
	e.stateAtime = make(map[uint32]int64)
	e.stateMtime = make(map[uint32]int64)
	e.pending = make(map[uint32]struct{})
	e.queue.ClearAll()
	if e.cfg.SpongeNet {
		e.setStateLocked(e.netIP, StateStatic, time.Now().Unix())
		e.setStateLocked(e.broadcast, StateStatic, time.Now().Unix())
	}
	for ip := range e.myIPs {
		e.setAliveLocked(ip, e.myMAC)
	}
}

func (e *Engine) ClearARP() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.arpTable = make(map[uint32]ArpEntry)
}

func (e *Engine) GetIPState(ip uint32) (IPState, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state, ok := e.state[ip]
	if !ok {
		return IPState{}, false
	}
	entry := IPState{
		IP:         netutil.IPv4String(ip),
		State:      state.String(),
		Queue:      e.queue.Depth(ip),
		Rate:       e.queue.Rate(ip),
		StateMTime: e.stateMtime[ip],
		StateATime: e.stateAtime[ip],
	}
	return entry, true
}

func (e *Engine) GetARPEntry(ip uint32) (ARPState, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	entry, ok := e.arpTable[ip]
	if !ok {
		return ARPState{}, false
	}
	return ARPState{IP: netutil.IPv4String(ip), MAC: entry.MAC.String(), Time: entry.Time}, true
}

func (e *Engine) ForceLearning(seconds int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.learningLeft = seconds
}

func (e *Engine) SetSweepAtStart() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nextSweep = time.Now()
}

func (e *Engine) SetNextSweep(sec int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nextSweep = time.Now().Add(time.Duration(sec) * time.Second)
}
