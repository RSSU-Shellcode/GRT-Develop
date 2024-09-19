package option

import (
	"bytes"
	"errors"
)

// +------------+---------+---------+
// | magic mark | option1 | option2 |
// +------------+---------+---------+
// |    0xFC    |   var   |   var   |
// +------------+---------+---------+

const (
	// StubMagic is the mark of options stub.
	StubMagic = 0xFC

	// StubSize is the option stub total size at the runtime tail.
	StubSize = 64
)

// options offset of the option stub.
const (
	OptOffsetNotEraseInstruction   = 1
	OptOffsetNotAdjustProtect      = 2
	OptOffsetNotTrackCurrentThread = 3
)

// Options contains options about Gleam-RT.
type Options struct {
	// not erase runtime instructions after call Runtime_M.Exit.
	NotEraseInstruction bool

	// not adjust current memory page protect for erase runtime.
	NotAdjustProtect bool

	// track current thread for some special executable file like Golang.
	TrackCurrentThread bool
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
	stub[OptOffsetNotTrackCurrentThread] = opt
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
	if stub[OptOffsetNotEraseInstruction] != 0 {
		opts.NotEraseInstruction = true
	}
	if stub[OptOffsetNotAdjustProtect] != 0 {
		opts.NotAdjustProtect = true
	}
	if stub[OptOffsetNotTrackCurrentThread] != 0 {
		opts.TrackCurrentThread = true
	}
	return &opts, nil
}
