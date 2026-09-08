package engine

import (
	"fmt"
	"strings"
)

type State int

const (
	StateNone   State = -99
	StateStatic State = -3
	StateDead   State = -2
	StateAlive  State = -1
)

func Pending(n int) State {
	return State(n)
}

func (s State) PendingCount() (int, bool) {
	if s >= 0 {
		return int(s), true
	}
	return 0, false
}

func (s State) String() string {
	switch s {
	case StateNone:
		return "NONE"
	case StateStatic:
		return "STATIC"
	case StateDead:
		return "DEAD"
	case StateAlive:
		return "ALIVE"
	}
	if s >= 0 {
		return fmt.Sprintf("PENDING(%d)", int(s))
	}
	return "NONE"
}

type UpdateFlags uint8

const (
	UpdateReply      UpdateFlags = 1 << 0
	UpdateRequest    UpdateFlags = 1 << 1
	UpdateGratuitous UpdateFlags = 1 << 2
	UpdateNone       UpdateFlags = 0
	UpdateAll        UpdateFlags = UpdateReply | UpdateRequest | UpdateGratuitous
)

var updateFlagNames = map[UpdateFlags]string{
	UpdateReply:      "reply",
	UpdateRequest:    "request",
	UpdateGratuitous: "gratuitous",
}

func ParseUpdateFlags(spec string) (UpdateFlags, error) {
	if strings.TrimSpace(spec) == "" {
		return UpdateNone, nil
	}
	flags := UpdateNone
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		negate := false
		if strings.HasPrefix(part, "!") {
			negate = true
			part = strings.TrimPrefix(part, "!")
		}
		if part == "none" {
			part = "all"
			negate = !negate
		}
		var bit UpdateFlags
		switch part {
		case "all":
			bit = UpdateAll
		case "reply":
			bit = UpdateReply
		case "request":
			bit = UpdateRequest
		case "gratuitous":
			bit = UpdateGratuitous
		default:
			return UpdateNone, fmt.Errorf("invalid arp-update-method: %s", part)
		}
		if negate {
			flags &^= bit
			continue
		}
		flags |= bit
	}
	return flags, nil
}

func (f UpdateFlags) Strings() []string {
	if f == UpdateNone {
		return []string{"none"}
	}
	var out []string
	for bit, name := range updateFlagNames {
		if f&bit != 0 {
			out = append(out, name)
		}
	}
	return out
}

type EventMask uint16

const (
	EventIO     EventMask = 0x0001
	EventAlien  EventMask = 0x0002
	EventSpoof  EventMask = 0x0004
	EventStatic EventMask = 0x0008
	EventSponge EventMask = 0x0010
	EventCtl    EventMask = 0x0020
	EventState  EventMask = 0x0040
	EventAll    EventMask = 0xffff
	EventNone   EventMask = 0x0000
)

var eventMaskNames = map[string]EventMask{
	"io":     EventIO,
	"alien":  EventAlien,
	"spoof":  EventSpoof,
	"static": EventStatic,
	"sponge": EventSponge,
	"ctl":    EventCtl,
	"state":  EventState,
	"all":    EventAll,
	"none":   EventNone,
}

func ParseEventMask(spec string, current EventMask) (EventMask, error) {
	if strings.TrimSpace(spec) == "" {
		return current, nil
	}
	mask := EventNone
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		negate := false
		if strings.HasPrefix(part, "!") {
			negate = true
			part = strings.TrimPrefix(part, "!")
		}
		value, ok := eventMaskNames[part]
		if !ok {
			return current, fmt.Errorf("invalid logmask: %s", part)
		}
		if part == "none" {
			value = EventAll
			negate = !negate
		}
		if negate {
			mask &^= value
			continue
		}
		mask |= value
	}
	return mask, nil
}

type LogLevel int

const (
	LevelEmerg LogLevel = iota
	LevelAlert
	LevelCrit
	LevelErr
	LevelWarning
	LevelNotice
	LevelInfo
	LevelDebug
)

var logLevelNames = map[string]LogLevel{
	"emerg":   LevelEmerg,
	"alert":   LevelAlert,
	"crit":    LevelCrit,
	"err":     LevelErr,
	"warning": LevelWarning,
	"notice":  LevelNotice,
	"info":    LevelInfo,
	"debug":   LevelDebug,
}

func ParseLogLevel(s string) (LogLevel, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	level, ok := logLevelNames[s]
	if !ok {
		return LevelInfo, fmt.Errorf("invalid loglevel: %s", s)
	}
	return level, nil
}

func (l LogLevel) String() string {
	for name, level := range logLevelNames {
		if l == level {
			return name
		}
	}
	return "info"
}
