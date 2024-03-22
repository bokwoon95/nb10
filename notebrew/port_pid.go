//go:build !windows

package main

func PortPid(port uint16) (pid int, err error) {
	return 0, nil
}
