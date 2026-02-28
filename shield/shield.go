package shield

import (
	"embed"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

// The role of the payload loader is used to decrypt payload
// in the tail section to a new RWX page, then create thread at
// the decrypted payload(default loader template).
var (
	//go:embed template/shield_x86.asm
	defaultTemplateX86 string

	//go:embed template/shield_x64.asm
	defaultTemplateX64 string
)

var (
	registerX86 = []string{
		"eax", "ebx", "ecx", "edx",
		"ebp", "edi", "esi",
	}

	registerX64 = []string{
		"rax", "rbx", "rcx", "rdx",
		"rbp", "rdi", "rsi",
		"r8", "r9", "r10", "r11",
		"r12", "r13", "r14", "r15",
	}
)

func (gen *Generator) buildShield() ([]byte, error) {
	return nil, nil
}

func (gen *Generator) buildRandomRegisterMap() map[string]string {
	var reg []string
	switch gen.arch {
	case 32:
		reg = slices.Clone(registerX86)
	case 64:
		reg = slices.Clone(registerX64)
	}
	gen.regBox = reg
	register := make(map[string]string, 16)
	switch gen.arch {
	case 32:
		for _, reg := range registerX86 {
			register[reg] = gen.selectRegister()
		}
	case 64:
		for _, reg := range registerX64 {
			register[reg] = gen.selectRegister()
		}
		gen.buildLowBitRegisterMap(register)
	}
	return register
}

func (gen *Generator) buildLowBitRegisterMap(register map[string]string) {
	// build register map about low dword
	low := make(map[string]string, len(register))
	for reg, act := range register {
		low[toRegDWORD(reg)] = toRegDWORD(act)
	}
	maps.Copy(register, low)
}

// selectRegister is used to make sure each register will be selected once.
func (gen *Generator) selectRegister() string {
	idx := gen.rand.Intn(len(gen.regBox))
	reg := gen.regBox[idx]
	// remove selected register
	gen.regBox = append(gen.regBox[:idx], gen.regBox[idx+1:]...)
	return reg
}

// convert r8 -> r8d, rax -> eax
func toRegDWORD(reg string) string {
	_, err := strconv.Atoi(reg[1:])
	if err == nil {
		return reg + "d"
	}
	return strings.ReplaceAll(reg, "r", "e")
}
