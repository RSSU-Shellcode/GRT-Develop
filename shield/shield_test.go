package shield

import (
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

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
	ctx := &testShieldArgs{
		CriticalAddress:     uintptr(unsafe.Pointer(&critical[0])),
		CriticalSize:        uintptr(len(critical)),
		VirtualProtect:      procVirtualProtect.Addr(),
		WaitForSingleObject: procWaitForSingleObject.Addr(),
		Timer:               0, // TODO
		Key:                 0x12345678,
	}
	return ctx
}

func TestShield(t *testing.T) {
	generator := NewGenerator()

	critical := make([]byte, 8192)
	copy(critical, "runtime instruction")

	t.Run("x86", func(t *testing.T) {

	})

	t.Run("x64", func(t *testing.T) {
		ctx, err := generator.Generate(64, nil)
		require.NoError(t, err)

		shield := loadShellcode(t, ctx.Output)
		args := testNewShieldArgs(t, critical)

		r1, _, _ := syscallN(shield, uintptr(unsafe.Pointer(args)))
		require.Equal(t, uintptr(0x12345678), r1)
	})

	require.True(t, strings.HasPrefix(string(critical), "runtime instruction"))

	err := generator.Close()
	require.NoError(t, err)
}
