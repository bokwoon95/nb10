//go:build !windows

package main

import (
	"fmt"
	"os"
)

func exit(exitErr error) {
	fmt.Println(exitErr)
	os.Exit(1)
}
