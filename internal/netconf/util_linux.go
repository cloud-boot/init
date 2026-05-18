//go:build linux

package netconf

import "os"

func writeFile(path string, data []byte, mode os.FileMode) error {
	_ = os.MkdirAll(parentDir(path), 0o755)
	return os.WriteFile(path, data, mode)
}

func parentDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
