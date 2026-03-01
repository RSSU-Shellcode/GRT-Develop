package shield

import (
	"bytes"
	"embed"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"text/template"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

var (
	//go:embed template/shield_x86.asm
	defaultTemplateX86 string

	//go:embed template/shield_x64.asm
	defaultTemplateX64 string
)

var (
	regVolatileX86 = []string{
		"eax", "ecx", "edx",
	}

	regNonvolatileX86 = []string{
		"ebx", "ebp", "edi", "esi",
	}

	regVolatileX64 = []string{
		"rax", "rcx", "rdx",
		"r8", "r9", "r10", "r11",
	}

	regNonvolatileX64 = []string{
		"rbx", "rbp", "rdi", "rsi",
		"r12", "r13", "r14", "r15",
	}
)

type shieldCtx struct {
	// for replace registers
	RegV map[string]string
	RegN map[string]string
}

func (gen *Generator) buildShield() ([]byte, error) {
	var shield string
	switch gen.arch {
	case 32:
		shield = gen.getTemplateX86()
	case 64:
		shield = gen.getTemplateX64()
	}
	ctx := &shieldCtx{
		RegV: gen.buildVolatileRegisterMap(),
		RegN: gen.buildNonvolatileRegisterMap(),
	}
	tpl, err := template.New("shield").Parse(shield)
	if err != nil {
		return nil, fmt.Errorf("invalid shield template: %s", err)
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build shield source: %s", err)
	}
	output, err := gen.assemble(buf.String())
	if err != nil {
		return nil, fmt.Errorf("failed to assemble shield source: %s", err)
	}
	return output, nil
}

func (gen *Generator) getTemplateX86() string {
	tpl := gen.opts.TemplateX86
	if tpl != "" {
		return tpl
	}
	return defaultTemplateX86
}

func (gen *Generator) getTemplateX64() string {
	tpl := gen.opts.TemplateX64
	if tpl != "" {
		return tpl
	}
	return defaultTemplateX64
}

func (gen *Generator) buildVolatileRegisterMap() map[string]string {
	var reg []string
	switch gen.arch {
	case 32:
		reg = slices.Clone(regVolatileX86)
	case 64:
		reg = slices.Clone(regVolatileX64)
	}
	gen.regBox = reg
	register := make(map[string]string, len(reg))
	switch gen.arch {
	case 32:
		for _, reg := range regVolatileX86 {
			register[reg] = gen.selectRegister()
		}
	case 64:
		for _, reg := range regVolatileX64 {
			register[reg] = gen.selectRegister()
		}
		gen.buildLowBitRegisterMap(register)
	}
	return register
}

func (gen *Generator) buildNonvolatileRegisterMap() map[string]string {
	var reg []string
	switch gen.arch {
	case 32:
		reg = slices.Clone(regNonvolatileX86)
	case 64:
		reg = slices.Clone(regNonvolatileX64)
	}
	gen.regBox = reg
	register := make(map[string]string, len(reg))
	switch gen.arch {
	case 32:
		for _, reg := range regNonvolatileX86 {
			register[reg] = gen.selectRegister()
		}
	case 64:
		for _, reg := range regNonvolatileX64 {
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
