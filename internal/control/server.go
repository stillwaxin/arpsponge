package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"arpsponge/internal/engine"
	"arpsponge/internal/netutil"
	"arpsponge/internal/packet"
)

type Server struct {
	engine *engine.Engine
	logger *Logger
	mux    *http.ServeMux
}

func NewServer(engine *engine.Engine, logger *Logger) *Server {
	s := &Server{
		engine: engine,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/v1/health", s.handleHealth)
	s.mux.HandleFunc("/v1/status", s.handleStatus)
	s.mux.HandleFunc("/v1/ip", s.handleIPList)
	s.mux.HandleFunc("/v1/ip/", s.handleIPItem)
	s.mux.HandleFunc("/v1/arp", s.handleARPList)
	s.mux.HandleFunc("/v1/arp/", s.handleARPItem)
	s.mux.HandleFunc("/v1/config", s.handleConfig)
	s.mux.HandleFunc("/v1/log", s.handleLogTail)
	s.mux.HandleFunc("/v1/log/stream", s.handleLogStream)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.engine.Status())
}

func (s *Server) handleIPList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	stateFilter := strings.ToLower(r.URL.Query().Get("state"))
	items := s.engine.SnapshotState()
	filtered := items[:0]
	for _, item := range items {
		itemState := strings.ToLower(item.State)
		match := stateFilter == "" || itemState == stateFilter
		if !match && stateFilter == "pending" && strings.HasPrefix(itemState, "pending") {
			match = true
		}
		if match {
			filtered = append(filtered, item)
		}
	}
	items = filtered

	sort.Slice(items, func(i, j int) bool {
		a, _ := netutil.ParseIPv4String(items[i].IP)
		b, _ := netutil.ParseIPv4String(items[j].IP)
		return a < b
	})

	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleIPItem(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/ip/")
	if path == "" {
		writeError(w, http.StatusNotFound, "missing ip")
		return
	}
	parts := strings.Split(path, "/")
	ipStr := parts[0]
	if ipStr == "clear" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.engine.ClearAllState()
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	ip, err := netutil.ParseIPv4String(ipStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, ok := s.engine.GetIPState(ip)
			if !ok {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			writeJSON(w, http.StatusOK, item)
			return
		case http.MethodPost:
			writeError(w, http.StatusNotFound, "unknown endpoint")
			return
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
	}

	switch parts[1] {
	case "state":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			State string `json:"state"`
			MAC   string `json:"mac"`
			Count *int   `json:"count"`
		}
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		state, err := parseState(req.State, req.Count)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		var mac packet.MAC
		if req.MAC != "" {
			mac, err = packet.ParseMAC(req.MAC)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid mac")
				return
			}
		}
		if err := s.engine.SetIPState(ip, state, mac); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	case "clear":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.engine.ClearIPState(ip)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	default:
		writeError(w, http.StatusNotFound, "unknown endpoint")
	}
}

func (s *Server) handleARPList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	items := s.engine.SnapshotARP()
	sort.Slice(items, func(i, j int) bool {
		a, _ := netutil.ParseIPv4String(items[i].IP)
		b, _ := netutil.ParseIPv4String(items[j].IP)
		return a < b
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleARPItem(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/arp/")
	if path == "" {
		writeError(w, http.StatusNotFound, "missing ip")
		return
	}
	parts := strings.Split(path, "/")
	ipStr := parts[0]
	if ipStr == "clear" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.engine.ClearARP()
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	ip, err := netutil.ParseIPv4String(ipStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}

	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		item, ok := s.engine.GetARPEntry(ip)
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, item)
		return
	}

	writeError(w, http.StatusNotFound, "unknown endpoint")
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.engine.Config()
		writeJSON(w, http.StatusOK, toConfigView(cfg))
	case http.MethodPost:
		var req configUpdate
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		err := s.engine.UpdateConfig(func(cfg *engine.Config) error {
			return req.apply(cfg)
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		cfg := s.engine.Config()
		s.logger.SetLevel(cfg.LogLevel)
		s.logger.SetMask(cfg.LogMask)
		writeJSON(w, http.StatusOK, toConfigView(cfg))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleLogTail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tail := 100
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			tail = n
		}
	}
	entries := s.logger.Tail(tail)
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Server) handleLogStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	ch, cancel := s.logger.Subscribe()
	defer cancel()

	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case entry := <-ch:
			fmt.Fprint(w, "data: ")
			if err := enc.Encode(entry); err != nil {
				return
			}
			fmt.Fprint(w, "\n")
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type configView struct {
	QueueDepth      int      `json:"queue_depth"`
	MaxRate         float64  `json:"max_rate"`
	ArpAge          int      `json:"arp_age"`
	MaxPending      int      `json:"max_pending"`
	Proberate       float64  `json:"proberate"`
	FloodProtection float64  `json:"flood_protection"`
	LearnSeconds    int      `json:"learning"`
	LogLevel        string   `json:"log_level"`
	LogMask         string   `json:"log_mask"`
	Dummy           bool     `json:"dummy"`
	Passive         bool     `json:"passive"`
	Static          bool     `json:"static"`
	Gratuitous      bool     `json:"gratuitous"`
	SpongeNet       bool     `json:"sponge_network"`
	SweepPeriod     int      `json:"sweep_period"`
	SweepAge        int      `json:"sweep_age"`
	SweepSkipAlive  bool     `json:"sweep_skip_alive"`
	ArpUpdateMethod []string `json:"arp_update_method"`
}

func toConfigView(cfg engine.Config) configView {
	return configView{
		QueueDepth:      cfg.QueueDepth,
		MaxRate:         cfg.MaxRate,
		ArpAge:          cfg.ArpAge,
		MaxPending:      cfg.MaxPending,
		Proberate:       cfg.Proberate,
		FloodProtection: cfg.FloodProtection,
		LearnSeconds:    cfg.LearnSeconds,
		LogLevel:        cfg.LogLevel.String(),
		LogMask:         maskToString(cfg.LogMask),
		Dummy:           cfg.Dummy,
		Passive:         cfg.Passive,
		Static:          cfg.Static,
		Gratuitous:      cfg.Gratuitous,
		SpongeNet:       cfg.SpongeNet,
		SweepPeriod:     cfg.SweepPeriod,
		SweepAge:        cfg.SweepAge,
		SweepSkipAlive:  cfg.SweepSkipAlive,
		ArpUpdateMethod: cfg.ArpUpdateFlags.Strings(),
	}
}

type configUpdate struct {
	QueueDepth      *int     `json:"queue_depth"`
	MaxRate         *float64 `json:"max_rate"`
	ArpAge          *int     `json:"arp_age"`
	MaxPending      *int     `json:"max_pending"`
	Proberate       *float64 `json:"proberate"`
	FloodProtection *float64 `json:"flood_protection"`
	LearnSeconds    *int     `json:"learning"`
	LogLevel        *string  `json:"log_level"`
	LogMask         *string  `json:"log_mask"`
	Dummy           *bool    `json:"dummy"`
	Passive         *bool    `json:"passive"`
	Static          *bool    `json:"static"`
	Gratuitous      *bool    `json:"gratuitous"`
	SpongeNet       *bool    `json:"sponge_network"`
	SweepPeriod     *int     `json:"sweep_period"`
	SweepAge        *int     `json:"sweep_age"`
	SweepSkipAlive  *bool    `json:"sweep_skip_alive"`
	ArpUpdateMethod *string  `json:"arp_update_method"`
}

func (u *configUpdate) apply(cfg *engine.Config) error {
	if u.QueueDepth != nil {
		cfg.QueueDepth = *u.QueueDepth
	}
	if u.MaxRate != nil {
		cfg.MaxRate = *u.MaxRate
	}
	if u.ArpAge != nil {
		cfg.ArpAge = *u.ArpAge
	}
	if u.MaxPending != nil {
		cfg.MaxPending = *u.MaxPending
	}
	if u.Proberate != nil {
		cfg.Proberate = *u.Proberate
	}
	if u.FloodProtection != nil {
		cfg.FloodProtection = *u.FloodProtection
	}
	if u.LearnSeconds != nil {
		cfg.LearnSeconds = *u.LearnSeconds
	}
	if u.LogLevel != nil {
		level, err := engine.ParseLogLevel(*u.LogLevel)
		if err != nil {
			return err
		}
		cfg.LogLevel = level
	}
	if u.LogMask != nil {
		mask, err := engine.ParseEventMask(*u.LogMask, cfg.LogMask)
		if err != nil {
			return err
		}
		cfg.LogMask = mask
	}
	if u.Dummy != nil {
		cfg.Dummy = *u.Dummy
	}
	if u.Passive != nil {
		cfg.Passive = *u.Passive
	}
	if u.Static != nil {
		cfg.Static = *u.Static
	}
	if u.Gratuitous != nil {
		cfg.Gratuitous = *u.Gratuitous
	}
	if u.SpongeNet != nil {
		cfg.SpongeNet = *u.SpongeNet
	}
	if u.SweepPeriod != nil {
		cfg.SweepPeriod = *u.SweepPeriod
	}
	if u.SweepAge != nil {
		cfg.SweepAge = *u.SweepAge
	}
	if u.SweepSkipAlive != nil {
		cfg.SweepSkipAlive = *u.SweepSkipAlive
	}
	if u.ArpUpdateMethod != nil {
		flags, err := engine.ParseUpdateFlags(*u.ArpUpdateMethod)
		if err != nil {
			return err
		}
		cfg.ArpUpdateFlags = flags
	}
	return nil
}

func parseState(s string, count *int) (engine.State, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "alive":
		return engine.StateAlive, nil
	case "dead":
		return engine.StateDead, nil
	case "static":
		return engine.StateStatic, nil
	case "pending":
		n := 0
		if count != nil {
			n = *count
		}
		if n < 0 {
			return 0, fmt.Errorf("pending count must be >= 0")
		}
		return engine.Pending(n), nil
	default:
		return 0, fmt.Errorf("invalid state")
	}
}

func maskToString(mask engine.EventMask) string {
	if mask == engine.EventAll {
		return "all"
	}
	if mask == engine.EventNone {
		return "none"
	}
	var parts []string
	for name, value := range map[string]engine.EventMask{
		"io":     engine.EventIO,
		"alien":  engine.EventAlien,
		"spoof":  engine.EventSpoof,
		"static": engine.EventStatic,
		"sponge": engine.EventSponge,
		"ctl":    engine.EventCtl,
		"state":  engine.EventState,
	} {
		if mask&value != 0 {
			parts = append(parts, name)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
