//go:build !windows

package main

import (
	"fmt"
	"os"
)

func exit(exitErr error) {
	fmt.Println(exitErr)
	pressAnyKeyToExit()
	os.Exit(1)
}
