//go:build !windows

package shield

import (
	"syscall"
	"testing"
)

func testNewShieldArgs(t *testing.T, critical []byte) *testShieldArgs {
	return nil
}

func testDeployShield(t *testing.T, shield []byte) uintptr {
	return 0
}

func loadShellcode(t *testing.T, sc []byte) uintptr {
	return 0
}

// for cross-compile
//
//go:uintptrescapes
func syscallN(proc uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return 0, 0, 0
}
