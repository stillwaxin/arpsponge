//go:build !linux

package linux

import (
	"context"
	"errors"
	"testing"
	"time"

	"arpsponge/internal/packet"
)

func TestUnsupportedPlatformAPIsReturnErrUnsupportedPlatform(t *testing.T) {
	if _, err := GetInterfaceInfo("en0"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("GetInterfaceInfo error = %v, want ErrUnsupportedPlatform", err)
	}
	if _, err := OpenCapture("en0", 512, true, time.Millisecond); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("OpenCapture error = %v, want ErrUnsupportedPlatform", err)
	}
	if _, err := ListenUnix(t.TempDir()+"/control.sock", "", "", 0o600); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("ListenUnix error = %v, want ErrUnsupportedPlatform", err)
	}

	capture := &Capture{}
	if err := capture.Run(context.Background(), func(packet.Packet) {}); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Run error = %v, want ErrUnsupportedPlatform", err)
	}
	if err := capture.SendARP(packet.ARP{}, packet.MAC{}, packet.MAC{}); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("SendARP error = %v, want ErrUnsupportedPlatform", err)
	}
	capture.Close()
}
