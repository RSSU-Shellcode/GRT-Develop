package shield

import (
	"embed"
	"io"
	"io/fs"
)

// The role of the junk code is to make the instruction sequence
// as featureless as possible.
var (
	//go:embed junk/*_x86.asm
	defaultJunkCodeFSX86 embed.FS

	//go:embed junk/*_x64.asm
	defaultJunkCodeFSX64 embed.FS

	defaultJunkCodeX86 = readJunkCodeTemplates(defaultJunkCodeFSX86)
	defaultJunkCodeX64 = readJunkCodeTemplates(defaultJunkCodeFSX64)
)

func readJunkCodeTemplates(efs embed.FS) []string {
	var templates []string
	err := fs.WalkDir(efs, ".", func(name string, entry fs.DirEntry, _ error) error {
		if entry.IsDir() {
			return nil
		}
		file, err := efs.Open(name)
		if err != nil {
			panic(err)
		}
		data, err := io.ReadAll(file)
		if err != nil {
			panic(err)
		}
		templates = append(templates, string(data))
		return nil
	})
	if err != nil {
		panic(err)
	}
	return templates
}

type junkCodeCtx struct {
	// for replace registers
	Reg map[string]string

	// for insert random instruction pair
	Switch map[string]bool

	// for random immediate data
	BYTE  map[string]int8
	WORD  map[string]int16
	DWORD map[string]int32
	QWORD map[string]int64

	// for random immediate data with [0, 32) and [0, 64)
	Less32 map[string]int
	Less64 map[string]int
}

func (gen *Generator) getJunkCodeX86() []string {
	if len(gen.opts.JunkCodeX86) > 0 {
		return gen.opts.JunkCodeX86
	}
	return defaultJunkCodeX86
}

func (gen *Generator) getJunkCodeX64() []string {
	if len(gen.opts.JunkCodeX64) > 0 {
		return gen.opts.JunkCodeX64
	}
	return defaultJunkCodeX64
}
