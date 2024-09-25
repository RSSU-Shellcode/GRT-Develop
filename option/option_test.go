package option

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

var template []byte

func init() {
	inst := bytes.Repeat([]byte{0xFF}, 64)
	stub := bytes.Repeat([]byte{0x00}, StubSize)
	stub[0] = StubMagic
	template = append(inst, stub...)
}

func TestSet(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := &Options{
			NotEraseInstruction: true,
			NotAdjustProtect:    true,
			TrackCurrentThread:  true,
		}
		output, err := Set(template, opts)
		require.NoError(t, err)
		o, err := Get(output, 64)
		require.NoError(t, err)
		require.Equal(t, opts, o)

		output, err = Set(template, nil)
		require.NoError(t, err)
		o, err = Get(output, 64)
		require.NoError(t, err)
		opts = &Options{
			NotEraseInstruction: false,
			NotAdjustProtect:    false,
			TrackCurrentThread:  false,
		}
		require.Equal(t, opts, o)
	})

	t.Run("invalid runtime shellcode template", func(t *testing.T) {
		output, err := Set(nil, nil)
		require.EqualError(t, err, "invalid runtime shellcode template")
		require.Nil(t, output)
	})

	t.Run("invalid runtime option stub", func(t *testing.T) {
		tpl := make([]byte, StubSize+64)

		output, err := Set(tpl, nil)
		require.EqualError(t, err, "invalid runtime option stub")
		require.Nil(t, output)
	})
}

func TestGet(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		opts := &Options{
			NotEraseInstruction: true,
			NotAdjustProtect:    true,
			TrackCurrentThread:  true,
		}
		output, err := Set(template, opts)
		require.NoError(t, err)

		o, err := Get(output, 64)
		require.NoError(t, err)
		require.Equal(t, opts, o)
	})

	t.Run("invalid runtime shellcode", func(t *testing.T) {
		opts, err := Get(nil, 0)
		require.EqualError(t, err, "invalid runtime shellcode")
		require.Nil(t, opts)
	})

	t.Run("invalid offset to the option stub", func(t *testing.T) {
		tpl := make([]byte, StubSize+64)

		opts, err := Get(tpl, len(tpl))
		require.EqualError(t, err, "invalid offset to the option stub")
		require.Nil(t, opts)
	})

	t.Run("invalid runtime option stub", func(t *testing.T) {
		tpl := make([]byte, StubSize+64)

		opts, err := Get(tpl, len(tpl)-StubSize)
		require.EqualError(t, err, "invalid runtime option stub")
		require.Nil(t, opts)
	})
}

func TestFlag(t *testing.T) {
	opts := Options{
		NotEraseInstruction: true,
		NotAdjustProtect:    true,
		TrackCurrentThread:  true,
	}
	Flag(&opts)

	expected := Options{}
	require.Equal(t, expected, opts)
}
