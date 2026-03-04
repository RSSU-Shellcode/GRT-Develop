package shield

import (
	"debug/pe"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procVirtualProtect       = modKernel32.NewProc("VirtualProtect")
	procWaitForSingleObject  = modKernel32.NewProc("WaitForSingleObject")
	procCreateWaitableTimerA = modKernel32.NewProc("CreateWaitableTimerA")
	procSetWaitableTimer     = modKernel32.NewProc("SetWaitableTimer")
)

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

// try to write shield in .text section
func testDeployShield(t *testing.T, shield []byte) uintptr {
	exe, err := os.Executable()
	require.NoError(t, err)
	img, err := pe.Open(exe)
	require.NoError(t, err)

	text := img.Section(".text")
	require.NotNil(t, text)
	cave := text.VirtualSize - text.Size
	if int(cave) < len(shield) {
		return loadShellcode(t, shield)
	}

	peb := windows.RtlGetCurrentPeb()
	address := peb.ImageBaseAddress + 0x1000 + uintptr(text.Size)
	size := uintptr(len(shield))
	var old uint32
	err = windows.VirtualProtect(address, size, windows.PAGE_READWRITE, &old)
	require.NoError(t, err)

	dst := unsafe.Slice((*byte)(unsafe.Pointer(address)), size)
	copy(dst, shield)

	err = windows.VirtualProtect(address, size, old, &old)
	require.NoError(t, err)
	return address
}

func loadShellcode(t *testing.T, sc []byte) uintptr {
	size := uintptr(len(sc))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	scAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(scAddr)), size)
	copy(dst, sc)
	return scAddr
}

// for cross-compile
//
//go:uintptrescapes
func syscallN(proc uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.SyscallN(proc, args...)
}
