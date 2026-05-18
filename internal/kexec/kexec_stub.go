//go:build !linux

package kexec

import "errors"

func Load(_, _, _ string) error { return errors.New("kexec: linux-only") }
func Boot() error               { return errors.New("kexec: linux-only") }
