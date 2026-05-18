//go:build !linux

package kexec

import "testing"

func TestStubsReturnError(t *testing.T) {
	if err := Load("k", "i", ""); err == nil {
		t.Error("Load should error on non-linux")
	}
	if err := Boot(); err == nil {
		t.Error("Boot should error on non-linux")
	}
}
