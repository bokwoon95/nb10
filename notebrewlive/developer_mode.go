//go:build dev
// +build dev

package main

import (
	"os"
	"path/filepath"
	"runtime"
)

func init() {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("developer mode enabled but cannot determine source file location.")
	}
	RuntimeFS = os.DirFS(filepath.Dir(file))
}
