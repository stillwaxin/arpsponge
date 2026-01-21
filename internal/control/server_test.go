package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"arpsponge/internal/engine"
	"arpsponge/internal/netutil"
	"arpsponge/internal/packet"
)

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

func mustJSON(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bytes.NewReader(data)
}
