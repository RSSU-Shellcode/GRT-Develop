package shield

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

const testSleepTime = 1000 // millisecond

type testShieldArgs struct {
	CriticalAddress     uintptr
	CriticalSize        uintptr
	VirtualProtect      uintptr
	WaitForSingleObject uintptr
	Timer               uintptr
	Key                 uintptr
}

func TestShield(t *testing.T) {
	generator := NewGenerator()

	critical := make([]byte, 8192)
	copy(critical, "runtime instruction")
	criticalAddr := uintptr(unsafe.Pointer(&critical[0]))

	t.Run("x86", func(t *testing.T) {
		ctx, err := generator.Generate(32, nil)
		require.NoError(t, err)
		fmt.Println("size:", len(ctx.Output))

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}

		shield := testDeployShield(t, ctx.Output)
		fmt.Printf("data address:   0x%X\n", criticalAddr)
		fmt.Printf("shield address: 0x%X\n", shield)
		args := testNewShieldArgs(t, critical)
		now := time.Now()

		_, _, _ = syscallN(shield, uintptr(unsafe.Pointer(args)))

		require.Greater(t, time.Since(now), time.Duration(testSleepTime)*time.Millisecond)
		require.True(t, strings.HasPrefix(string(critical), "runtime instruction"))
	})

	t.Run("x64", func(t *testing.T) {
		ctx, err := generator.Generate(64, nil)
		require.NoError(t, err)
		fmt.Println("size:", len(ctx.Output))

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}

		shield := testDeployShield(t, ctx.Output)
		fmt.Printf("data address:   0x%X\n", criticalAddr)
		fmt.Printf("shield address: 0x%X\n", shield)
		args := testNewShieldArgs(t, critical)
		now := time.Now()

		_, _, _ = syscallN(shield, uintptr(unsafe.Pointer(args)))

		require.Greater(t, time.Since(now), time.Duration(testSleepTime)*time.Millisecond)
		require.True(t, strings.HasPrefix(string(critical), "runtime instruction"))
	})

	err := generator.Close()
	require.NoError(t, err)
}
