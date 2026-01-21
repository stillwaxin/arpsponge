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
