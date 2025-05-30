package option

import (
	"bytes"
	"errors"
	"flag"
)

// +------------+---------+---------+-----------+
// | magic mark | option1 | option2 | option... |
// +------------+---------+---------+-----------+
// |    0xFC    |   var   |   var   |    var    |
// +------------+---------+---------+-----------+

const (
	// StubSize is the option stub total size at the runtime tail.
	StubSize = 64

	// StubMagic is the mark of options stub.
	StubMagic = 0xFC
)

// options offset of the option stub.
const (
	OptOffsetDisableSysmon = iota + 1
	OptOffsetDisableWatchdog
	OptOffsetNotEraseInstruction
	OptOffsetNotAdjustProtect
	OptOffsetTrackCurrentThread
)

// Options contains options about Gleam-RT.
type Options struct {
	// disable sysmon for implement single thread model.
	DisableSysmon bool `toml:"disable_sysmon" json:"disable_sysmon"`

	// disable watchdog for implement single thread model.
	// it will overwrite the control from upper module.
	DisableWatchdog bool `toml:"disable_watchdog" json:"disable_watchdog"`

	// not erase runtime instructions after call Runtime_M.Exit.
	NotEraseInstruction bool `toml:"not_erase_instruction" json:"not_erase_instruction"`

	// not adjust current memory page protect for erase runtime.
	NotAdjustProtect bool `toml:"not_adjust_protect" json:"not_adjust_protect"`

	// track current thread for test or debug mode.
	// it maybe improved the single thread model.
	TrackCurrentThread bool `toml:"track_current_thread" json:"track_current_thread"`
}

// Set is used to adjust options in the runtime shellcode template.
func Set(tpl []byte, opts *Options) ([]byte, error) {
	// check shellcode runtime template is valid
	if len(tpl) < StubSize {
		return nil, errors.New("invalid runtime shellcode template")
	}
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	if !bytes.Equal(tpl[len(tpl)-StubSize:], stub) {
		return nil, errors.New("invalid runtime option stub")
	}
	// write options to stub
	if opts == nil {
		opts = new(Options)
	}
	output := make([]byte, len(tpl))
	copy(output, tpl)
	stub = output[len(output)-StubSize:]
	var opt byte
	if opts.DisableSysmon {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetDisableSysmon] = opt
	if opts.DisableWatchdog {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetDisableWatchdog] = opt
	if opts.NotEraseInstruction {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetNotEraseInstruction] = opt
	if opts.NotAdjustProtect {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetNotAdjustProtect] = opt
	if opts.TrackCurrentThread {
		opt = 1
	} else {
		opt = 0
	}
	stub[OptOffsetTrackCurrentThread] = opt
	return output, nil
}

// Get is used to read options from the runtime shellcode option stub.
func Get(sc []byte, offset int) (*Options, error) {
	if len(sc) < StubSize {
		return nil, errors.New("invalid runtime shellcode")
	}
	if offset < 0 || len(sc)-offset < StubSize {
		return nil, errors.New("invalid offset to the option stub")
	}
	if sc[offset] != StubMagic {
		return nil, errors.New("invalid runtime option stub")
	}
	// read option from stub
	opts := Options{}
	stub := sc[offset:]
	if stub[OptOffsetDisableSysmon] != 0 {
		opts.DisableSysmon = true
	}
	if stub[OptOffsetDisableWatchdog] != 0 {
		opts.DisableWatchdog = true
	}
	if stub[OptOffsetNotEraseInstruction] != 0 {
		opts.NotEraseInstruction = true
	}
	if stub[OptOffsetNotAdjustProtect] != 0 {
		opts.NotAdjustProtect = true
	}
	if stub[OptOffsetTrackCurrentThread] != 0 {
		opts.TrackCurrentThread = true
	}
	return &opts, nil
}

// Flag is used to read options from command line.
func Flag(opts *Options) {
	flag.BoolVar(
		&opts.DisableSysmon, "grt-ds", false,
		"Gleam-RT: disable sysmon for implement single thread model",
	)
	flag.BoolVar(
		&opts.DisableWatchdog, "grt-dw", false,
		"Gleam-RT: disable watchdog for implement single thread model.",
	)
	flag.BoolVar(
		&opts.NotEraseInstruction, "grt-nei", false,
		"Gleam-RT: not erase runtime instructions after runtime stop",
	)
	flag.BoolVar(
		&opts.NotAdjustProtect, "grt-nap", false,
		"Gleam-RT: not adjust current memory page protect for erase runtime",
	)
	flag.BoolVar(
		&opts.TrackCurrentThread, "grt-tct", false,
		"Gleam-RT: track current thread for test or debug mode",
	)
}
