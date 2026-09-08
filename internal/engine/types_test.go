package engine

import "testing"

func TestParseUpdateFlags(t *testing.T) {
	flags, err := ParseUpdateFlags("reply,request")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags&UpdateReply == 0 || flags&UpdateRequest == 0 {
		t.Fatalf("expected reply and request flags set")
	}

	flags, err = ParseUpdateFlags("none")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags != UpdateNone {
		t.Fatalf("expected none, got %v", flags)
	}
}

func TestParseEventMask(t *testing.T) {
	mask, err := ParseEventMask("!alien,io", EventAll)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mask != EventIO {
		t.Fatalf("expected only io mask, got %v", mask)
	}
}

func TestParseEventMaskNegation(t *testing.T) {
	for _, tt := range []struct {
		spec    string
		want    EventMask
		invalid bool
	}{
		{"all", EventAll, false}, {"all,!all,state", EventState, false}, {"all,!all", EventNone, false}, {"!all", EventNone, false}, {"none", EventNone, false}, {"!none", EventAll, false},
		{"all,!all,io", EventIO, false}, {"all,!io", EventAll &^ EventIO, false}, {"", EventCtl, false}, {"bogus", EventCtl, true},
	} {
		t.Run(tt.spec, func(t *testing.T) {
			got, err := ParseEventMask(tt.spec, EventCtl)
			if (err != nil) != tt.invalid || got != tt.want {
				t.Fatalf("got %v,%v want %v invalid=%v", got, err, tt.want, tt.invalid)
			}
		})
	}
}
