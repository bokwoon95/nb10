//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	// https://learn.microsoft.com/en-us/windows/console/getconsoleprocesslist
	getConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	// https://learn.microsoft.com/en-us/windows/console/setconsolemode
	setConsoleMode = kernel32.NewProc("SetConsoleMode")
)

func init() {
	// When an error happens, don't immediately exit the program because that would
	// cause the command prompt window to disappear and not give the user a chance
	// to look at the error message. Instead, present the user with a "Press any
	// key to exit..." prompt. But only if the user double clicked on the binary in
	// the first place. If run from the command line, do not present the user with
	// the prompt.
	exit = func(exitErr error) {
		// Detect if windows golang executable file is running via double click or
		// from cmd/shell terminator.
		// https://gist.github.com/yougg/213250cc04a52e2b853590b06f49d865
		//
		// Read a character from standard input in Go (without pressing Enter).
		// https://stackoverflow.com/a/17289208
		var pids [2]uint32
		var maxCount uint32 = 2
		processCount, _, _ := getConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids)), uintptr(maxCount))
		if processCount > 1 {
			os.Exit(1)
		}
		h := syscall.Handle(os.Stdin.Fd())
		var mode uint32
		err := syscall.GetConsoleMode(h, &mode)
		if err != nil {
			fmt.Println(exitErr)
			return
		}
		success, _, _ := setConsoleMode.Call(uintptr(h), 0)
		if success == 0 {
			fmt.Println(exitErr)
			return
		}
		defer setConsoleMode.Call(uintptr(h), uintptr(mode))
		fmt.Println(exitErr)
		fmt.Print("Press any key to exit...")
		os.Stdin.Read(make([]byte, 1))
		os.Exit(1)
	}
}
