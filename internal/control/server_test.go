package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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

func TestServerLogStreamFlushesInitialHeaders(t *testing.T) {
	srv := httptest.NewServer(newTestServer(t).Handler())
	defer srv.Close()

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(srv.URL + "/v1/log/stream")
	if err != nil {
		t.Fatalf("open idle log stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("stream content type = %q, want text/event-stream", got)
	}
}

func TestServerConfigRejectsInvalidUpdatesAtomically(t *testing.T) {
	for _, body := range []string{
		`{"queue_depth":0}`,
		`{"max_rate":-1}`,
		`{"arp_age":-1}`,
		`{"max_pending":-1}`,
		`{"proberate":-1}`,
		`{"flood_protection":-1}`,
		`{"learning":-1}`,
		`{"sweep_period":-1}`,
		`{"sweep_age":-1}`,
		`{"arp_age":9223372037}`,
		`{"learning":9223372037}`,
		`{"sweep_period":9223372037}`,
		`{"sweep_age":9223372037}`,
		`{"max_pending":0,"max_rate":-1}`,
		`{"max_rate":NaN}`,
		`{"max_rate":1e9999}`,
	} {
		t.Run(body, func(t *testing.T) {
			srv := newTestServer(t)
			before := srv.engine.Config()
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/config", strings.NewReader(body))
			srv.Handler().ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			if after := srv.engine.Config(); !reflect.DeepEqual(after, before) {
				t.Fatalf("invalid update changed config: got %#v, want %#v", after, before)
			}
		})
	}
}

func TestServerConfigAcceptsExplicitZeroAndFalse(t *testing.T) {
	srv := newTestServer(t)
	setTrue := httptest.NewRecorder()
	srv.Handler().ServeHTTP(setTrue, httptest.NewRequest(http.MethodPost, "/v1/config", strings.NewReader(`{"passive":true}`)))
	if setTrue.Code != http.StatusOK || !srv.engine.Config().Passive {
		t.Fatalf("could not establish passive=true before explicit false: %d %s", setTrue.Code, setTrue.Body.String())
	}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/config", strings.NewReader(`{"max_pending":0,"proberate":0,"learning":0,"passive":false}`))
	srv.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	cfg := srv.engine.Config()
	if cfg.MaxPending != 0 || cfg.Proberate != 0 || cfg.LearnSeconds != 0 || cfg.Passive {
		t.Fatalf("config = %#v, want explicit zero/false update", cfg)
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
