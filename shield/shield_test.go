package shield

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

const testSleepTime = 1000 // millisecond

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procVirtualProtect       = modKernel32.NewProc("VirtualProtect")
	procWaitForSingleObject  = modKernel32.NewProc("WaitForSingleObject")
	procCreateWaitableTimerA = modKernel32.NewProc("CreateWaitableTimerA")
	procSetWaitableTimer     = modKernel32.NewProc("SetWaitableTimer")
)

type testShieldArgs struct {
	CriticalAddress     uintptr
	CriticalSize        uintptr
	VirtualProtect      uintptr
	WaitForSingleObject uintptr
	Timer               uintptr
	Key                 uintptr
}

func testNewShieldArgs(t *testing.T, critical []byte) *testShieldArgs {
	hTimer, _, err := procCreateWaitableTimerA.Call(0, 0, 0)
	if hTimer == 0 {
		require.NoError(t, err)
	}
	dueTime := int64(-testSleepTime * 1000 * 10)
	ok, _, err := procSetWaitableTimer.Call(
		hTimer, uintptr(unsafe.Pointer(&dueTime)), 0, 0, 0, 1,
	)
	require.True(t, ok == 1, err)
	ctx := &testShieldArgs{
		CriticalAddress:     uintptr(unsafe.Pointer(&critical[0])),
		CriticalSize:        uintptr(len(critical)),
		VirtualProtect:      procVirtualProtect.Addr(),
		WaitForSingleObject: procWaitForSingleObject.Addr(),
		Timer:               hTimer,
		Key:                 0x12345678,
	}
	return ctx
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

		shield := loadShellcode(t, ctx.Output)
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

		shield := loadShellcode(t, ctx.Output)
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
