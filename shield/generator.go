package shield

import (
	cr "crypto/rand"
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/For-ACGN/go-keystone"
)

// Generator is the runtime shield generator.
type Generator struct {
	rand *rand.Rand

	// assembler engine
	ase32 *keystone.Engine
	ase64 *keystone.Engine

	// context arguments
	arch int
}

// Options contains options about generate shield.
type Options struct {
	// specify a random seed for generator.
	RandSeed int64 `toml:"rand_seed" json:"rand_seed"`

	// specify the x86 shield template.
	TemplateX86 string `toml:"template_x86" json:"template_x86"`

	// specify the x64 shield template.
	TemplateX64 string `toml:"template_x64" json:"template_x64"`
}

// NewGenerator is used to create a shield generator.
func NewGenerator() *Generator {
	var seed int64
	buf := make([]byte, 8)
	_, err := cr.Read(buf)
	if err == nil {
		seed = int64(binary.LittleEndian.Uint64(buf)) // #nosec G115
	} else {
		seed = time.Now().UTC().UnixNano()
	}
	generator := Generator{
		rand: rand.New(rand.NewSource(seed)), // #nosec
	}
	return &generator
}

func (gen *Generator) Generate() {

}

func (gen *Generator) initAssembler() error {
	var (
		ase *keystone.Engine
		err error
	)
	switch gen.arch {
	case 32:
		if gen.ase32 != nil {
			return nil
		}
		ase, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		if err != nil {
			return err
		}
		gen.ase32 = ase
	case 64:
		if gen.ase64 != nil {
			return nil
		}
		ase, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		if err != nil {
			return err
		}
		gen.ase64 = ase
	default:
		panic("unreachable code")
	}
	return ase.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
}
