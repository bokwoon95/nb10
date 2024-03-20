package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/netstat"
)

type StopCmd struct {
	Notebrew *nb10.Notebrew
	Stdout   io.Writer
	Port     uint16
}

func StopCommand(nbrew *nb10.Notebrew, configDir string, addr string, args ...string) (*StopCmd, error) {
	var cmd StopCmd
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Usage = func() {
		fmt.Fprintln(flagset.Output(), `Usage:
  lorem ipsum dolor sit amet
  consectetur adipiscing elit
Flags:`)
		flagset.PrintDefaults()
	}
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	if flagset.NArg() > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagset.Args(), " "))
	}
	n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimPrefix(addr, "localhost"), ":"))
	if err != nil {
		return nil, err
	}
	cmd.Port = uint16(n)
	return &cmd, nil
}

func (cmd *StopCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	sockTabEntries, err := netstat.TCPSocks(func(sockTabEntry *netstat.SockTabEntry) bool {
		return sockTabEntry.State == netstat.Listen && sockTabEntry.LocalAddr.Port == cmd.Port
	})
	if err != nil {
		return err
	}
	if len(sockTabEntries) == 0 {
		fmt.Fprintf(cmd.Stdout, "notebrew is not running\n")
		return nil
	}
	name := sockTabEntries[0].Process.Name
	pid := sockTabEntries[0].Process.Pid
	if runtime.GOOS == "windows" {
		killCmd := exec.Command("taskkill.exe", "/t", "/f", "/pid", strconv.Itoa(pid))
		err := killCmd.Run()
		if err != nil {
			return err
		}
	} else {
		killCmd := exec.Command("kill", strconv.Itoa(pid))
		err := killCmd.Run()
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(cmd.Stdout, "stopped %s (pid %d)\n", name, pid)
	return nil
}
