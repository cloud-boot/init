//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "cloud-boot-init is linux/amd64 only; cross-compile with GOOS=linux GOARCH=amd64")
	os.Exit(1)
}
