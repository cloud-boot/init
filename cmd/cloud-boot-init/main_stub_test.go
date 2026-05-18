//go:build !linux

package main

import (
	"os"
	"os/exec"
	"testing"
)

// TestMain_Stub spawns the test binary as a subprocess with BE_MAIN=1, which
// re-enters main() and lets us assert the exit code without taking down the
// test process. Standard Go cross-binary test pattern.
func TestMain_Stub(t *testing.T) {
	if os.Getenv("BE_MAIN") == "1" {
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMain_Stub")
	cmd.Env = append(os.Environ(), "BE_MAIN=1")
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.ExitCode())
	}
}
