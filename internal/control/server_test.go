package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"arpsponge/internal/engine"
	"arpsponge/internal/netutil"
	"arpsponge/internal/packet"
)

type deadlineResponseRecorder struct {
	*httptest.ResponseRecorder
	deadline    time.Time
	deadlineSet bool
}

func (r *deadlineResponseRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadline = deadline
	r.deadlineSet = true
	return nil
}

func (r *deadlineResponseRecorder) Flush() {}

type fakeSender struct{}

func (f *fakeSender) SendARP(_ packet.ARP, _ packet.MAC, _ packet.MAC) error {
	return nil
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	netCIDR, netIP, broadcast, prefixLen, err := netutil.ParseCIDRString("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	myIP, _ := netutil.ParseIPv4String("10.0.0.1")
	mac := packet.MustParseMAC("aa:bb:cc:dd:ee:ff")
	cfg := engine.DefaultConfig()
	cfg.InitState = engine.StateNone
	logger := NewLogger(64, engine.LevelDebug, engine.EventAll)
	eng := engine.New(cfg, "eth0", netCIDR, netIP, broadcast, prefixLen, myIP, mac, []uint32{myIP}, &fakeSender{}, logger)
	return NewServer(eng, logger)
}

func TestServerIPStateLifecycle(t *testing.T) {
	srv := newTestServer(t)

	payload := map[string]any{"state": "dead"}
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip/10.0.0.5/state", mustJSON(t, payload))
	srv.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	resp = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/ip/10.0.0.5", nil)
	srv.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var got struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.State != "DEAD" {
		t.Fatalf("expected DEAD, got %s", got.State)
	}
}

func TestServerConfigUpdate(t *testing.T) {
	srv := newTestServer(t)
	payload := map[string]any{"max_rate": 12.5, "log_level": "debug"}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/config", mustJSON(t, payload))
	srv.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var got struct {
		MaxRate  float64 `json:"max_rate"`
		LogLevel string  `json:"log_level"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.MaxRate != 12.5 {
		t.Fatalf("expected max_rate 12.5, got %f", got.MaxRate)
	}
	if got.LogLevel != "debug" {
		t.Fatalf("expected log_level debug, got %s", got.LogLevel)
	}
}

func TestServerConfigLearningUpdateRestartsLearningPeriod(t *testing.T) {
	srv := newTestServer(t)
	srv.engine.ForceLearning(0)
	payload := map[string]any{"learning": 2}

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/config", mustJSON(t, payload))
	srv.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	sourceIP, err := netutil.ParseIPv4String("10.0.0.7")
	if err != nil {
		t.Fatalf("parse source ip: %v", err)
	}
	targetIP, err := netutil.ParseIPv4String("10.0.0.8")
	if err != nil {
		t.Fatalf("parse target ip: %v", err)
	}
	arpRequest := packet.Packet{
		SrcMAC:    packet.MustParseMAC("00:11:22:33:44:08"),
		DstMAC:    packet.MustParseMAC("ff:ff:ff:ff:ff:ff"),
		EtherType: packet.EtherTypeARP,
		ARP: &packet.ARP{
			Opcode:    packet.ARPOpRequest,
			SenderMAC: packet.MustParseMAC("00:11:22:33:44:08"),
			SenderIP:  sourceIP,
			TargetIP:  targetIP,
		},
	}

	srv.engine.Tick(time.Now())
	srv.engine.HandlePacket(arpRequest)
	if _, ok := srv.engine.GetIPState(targetIP); ok {
		t.Fatal("ARP request was processed before the configured learning period ended")
	}

	srv.engine.Tick(time.Now())
	srv.engine.HandlePacket(arpRequest)
	state, ok := srv.engine.GetIPState(targetIP)
	if !ok {
		t.Fatal("ARP request was not processed after the configured learning period ended")
	}
	if state.State != "PENDING(0)" {
		t.Fatalf("got state %s after learning period, want PENDING(0)", state.State)
	}
}

func TestServerLogStreamClearsWriteDeadline(t *testing.T) {
	srv := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recorder := &deadlineResponseRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "/v1/log/stream", nil).WithContext(ctx)

	srv.Handler().ServeHTTP(recorder, req)

	if !recorder.deadlineSet {
		t.Fatal("log stream did not clear the server write deadline")
	}
	if !recorder.deadline.IsZero() {
		t.Fatalf("log stream write deadline = %s, want zero", recorder.deadline)
	}
}

func mustJSON(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bytes.NewReader(data)
}
