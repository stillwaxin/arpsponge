package packet

import "testing"

func TestParseMAC(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    MAC
		wantErr bool
	}{
		{name: "colon separated", input: "aa:bb:cc:dd:ee:ff", want: MAC{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
		{name: "hyphen separated", input: "AA-BB-CC-DD-EE-FF", want: MAC{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
		{name: "EUI-64 rejected", input: "00:11:22:33:44:55:66:77", wantErr: true},
		{name: "too short rejected", input: "aa:bb:cc:dd:ee", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMAC(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMAC(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMACIsZero(t *testing.T) {
	tests := []struct {
		name string
		mac  MAC
		want bool
	}{
		{name: "zero", mac: MAC{}, want: true},
		{name: "nonzero", mac: MAC{0, 0, 0, 0, 0, 1}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mac.IsZero(); got != tt.want {
				t.Fatalf("IsZero() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestMACUnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    MAC
		wantErr bool
	}{
		{name: "12 hex characters", input: "aabbccddeeff", want: MAC{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
		{name: "separated form", input: "aa:bb:cc:dd:ee:ff", want: MAC{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
		{name: "empty clears", input: "", want: MAC{}},
		{name: "invalid 12 hex characters", input: "aabbccddeefg", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MAC{1, 2, 3, 4, 5, 6}
			err := got.UnmarshalText([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
