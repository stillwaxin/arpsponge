package netutil

import (
	"errors"
	"testing"
)

func TestParseCIDRString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		network   uint32
		broadcast uint32
		prefix    int
		wantErr   bool
		wantError error
	}{
		{
			name:      "network address",
			input:     "192.0.2.0/24",
			network:   0xc0000200,
			broadcast: 0xc00002ff,
			prefix:    24,
		},
		{
			name:      "host address in network",
			input:     "192.0.2.17/28",
			network:   0xc0000210,
			broadcast: 0xc000021f,
			prefix:    28,
		},
		{
			name:      "default network",
			input:     "0.0.0.0/0",
			network:   0,
			broadcast: 0xffffffff,
			prefix:    0,
		},
		{
			name:      "IPv6 address",
			input:     "2001:db8::/32",
			wantErr:   true,
			wantError: ErrInvalidIPv4,
		},
		{
			name:    "invalid prefix",
			input:   "192.0.2.0/33",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, network, broadcast, prefix, err := ParseCIDRString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if tt.wantError != nil && !errors.Is(err, tt.wantError) {
					t.Fatalf("expected error %v, got %v", tt.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCIDRString(%q): %v", tt.input, err)
			}
			if network != tt.network || broadcast != tt.broadcast || prefix != tt.prefix {
				t.Fatalf("got network=%08x broadcast=%08x prefix=%d, want network=%08x broadcast=%08x prefix=%d", network, broadcast, prefix, tt.network, tt.broadcast, tt.prefix)
			}
		})
	}
}

func TestParseIPv4String(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint32
		wantErr error
	}{
		{name: "IPv4", input: "192.0.2.1", want: 0xc0000201},
		// net.ParseIP(...).To4() intentionally accepts IPv4-mapped IPv6.
		// Control API /v1/ip/ and /v1/arp/ paths use this helper, so preserve
		// that canonicalization as part of the current API behavior.
		{name: "IPv4-mapped IPv6", input: "::ffff:192.0.2.1", want: 0xc0000201},
		{name: "IPv6", input: "2001:db8::1", wantErr: ErrInvalidIPv4},
		{name: "invalid octet", input: "192.0.2.256", wantErr: ErrInvalidIPv4},
		{name: "empty", input: "", wantErr: ErrInvalidIPv4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPv4String(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIPv4String(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("got %08x, want %08x", got, tt.want)
			}
		})
	}
}

func TestInNetBoundaryPrefixes(t *testing.T) {
	tests := []struct {
		name      string
		ip        uint32
		network   uint32
		prefix    int
		wantInNet bool
	}{
		{name: "prefix zero accepts any address", ip: 0xffffffff, network: 0, prefix: 0, wantInNet: true},
		{name: "prefix thirty-two equal", ip: 0xc0000201, network: 0xc0000201, prefix: 32, wantInNet: true},
		{name: "prefix thirty-two different", ip: 0xc0000201, network: 0xc0000202, prefix: 32, wantInNet: false},
		{name: "prefix one matching", ip: 0x80000000, network: 0x80000001, prefix: 1, wantInNet: true},
		{name: "prefix one different", ip: 0x80000000, network: 0x00000001, prefix: 1, wantInNet: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InNet(tt.ip, tt.network, tt.prefix); got != tt.wantInNet {
				t.Fatalf("InNet(%08x, %08x, %d) = %t, want %t", tt.ip, tt.network, tt.prefix, got, tt.wantInNet)
			}
		})
	}
}
