package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bokwoon95/nb10"
)

type StartCmd struct {
	Notebrew  *nb10.Notebrew
	Stdout    io.Writer
	ConfigDir string
	Addr      string
}

func StartCommand(nbrew *nb10.Notebrew, configDir, addr string, args ...string) (*StartCmd, error) {
	var cmd StartCmd
	cmd.Notebrew = nbrew
	cmd.ConfigDir = configDir
	cmd.Addr = addr
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
	return &cmd, nil
}

func (cmd *StartCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	server, err := NewServer(cmd.Notebrew, cmd.ConfigDir, cmd.Addr)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return err
		}
		// WSAEADDRINUSE copied from
		// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
		const WSAEADDRINUSE = syscall.Errno(10048)
		if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
			if server.Addr == "localhost" || strings.HasPrefix(server.Addr, "localhost:") {
				fmt.Fprintln(cmd.Stdout, "notebrew is already running on http://" + server.Addr + "/files/")
				return nil
			}
			fmt.Fprintln(cmd.Stdout, "notebrew is already running (run `notebrew stop` to stop the process)")
			return nil
		}
		return err
	}
	// Swallow SIGHUP so that we can keep running even when the (SSH)
	// session ends (the user should use `notebrew stop` to stop the
	// process).
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for {
			<-ch
		}
	}()
	wait := make(chan os.Signal, 1)
	signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM)
	if server.Addr == ":443" {
		go func() {
			err := server.ServeTLS(listener, "", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintln(cmd.Stdout, err)
				close(wait)
			}
		}()
		go http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" && r.Method != "HEAD" {
				http.Error(w, "Use HTTPS", http.StatusBadRequest)
				return
			}
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			} else {
				host = net.JoinHostPort(host, "443")
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
		}))
		fmt.Fprintf(cmd.Stdout, startmsg, server.Addr)
	} else {
		go func() {
			err := server.Serve(listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintln(cmd.Stdout, err)
				close(wait)
			}
		}()
		if server.Addr == "localhost" || strings.HasPrefix(server.Addr, "localhost:") {
			fmt.Fprintf(cmd.Stdout, startmsg, "http://"+server.Addr+"/files/")
		} else {
			fmt.Fprintf(cmd.Stdout, startmsg, server.Addr)
		}
	}
	<-wait
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	server.Shutdown(ctx)
	return nil
}
