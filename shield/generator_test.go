package shield

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerator(t *testing.T) {
	generator := NewGenerator()

	t.Run("x86", func(t *testing.T) {
		ctx, err := generator.Generate(32, nil)
		require.NoError(t, err)
		fmt.Println("size:", len(ctx.Output))
		fmt.Println("seed:", ctx.Seed)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}

		testShield(t, ctx.Output)
	})

	t.Run("x64", func(t *testing.T) {
		ctx, err := generator.Generate(64, nil)
		require.NoError(t, err)
		fmt.Println("size:", len(ctx.Output))
		fmt.Println("seed:", ctx.Seed)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}

		testShield(t, ctx.Output)
	})

	t.Run("invalid arch", func(t *testing.T) {
		ctx, err := generator.Generate(123, nil)
		require.EqualError(t, err, "unsupported architecture: 123")
		require.Nil(t, ctx)
	})

	err := generator.Close()
	require.NoError(t, err)
}

func TestSpecificSeed(t *testing.T) {
	generator := NewGenerator()

	opts := &Options{
		RandSeed: 1234,
	}

	t.Run("x86", func(t *testing.T) {
		ctx1, err := generator.Generate(32, opts)
		require.NoError(t, err)
		ctx2, err := generator.Generate(32, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx2)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}

		testShield(t, ctx1.Output)
	})

	t.Run("x64", func(t *testing.T) {
		ctx1, err := generator.Generate(64, opts)
		require.NoError(t, err)
		ctx2, err := generator.Generate(64, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx2)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}

		testShield(t, ctx1.Output)
	})

	err := generator.Close()
	require.NoError(t, err)
}
