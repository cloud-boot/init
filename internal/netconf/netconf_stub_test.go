//go:build !linux

package netconf

import "testing"

func TestStubReturnsError(t *testing.T) {
	if _, err := Setup(""); err == nil {
		t.Error("Setup should error on non-linux")
	}
}
