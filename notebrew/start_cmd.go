package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/caddyserver/certmagic"
	"github.com/klauspost/cpuid/v2"
)

type StartCmd struct {
	Notebrew  *nb10.Notebrew
	Stdout    io.Writer
	ConfigDir string
}

func StartCommand(nbrew *nb10.Notebrew, configDir string, args ...string) (*StartCmd, error) {
	var cmd StartCmd
	cmd.Notebrew = nbrew
	cmd.ConfigDir = configDir
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
	var server http.Server
	switch cmd.Notebrew.Port {
	case 443:
		server.Addr = ":443"
		server.Handler = http.TimeoutHandler(cmd.Notebrew, 60*time.Second, "The server took too long to process your request.")
		server.ReadTimeout = 60 * time.Second
		server.WriteTimeout = 60 * time.Second
		server.IdleTimeout = 120 * time.Second
		staticCertConfig := certmagic.NewDefault()
		staticCertConfig.Storage = cmd.Notebrew.CertStorage
		if cmd.Notebrew.DNSProvider != nil {
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
					CA:        certmagic.DefaultACME.CA,
					TestCA:    certmagic.DefaultACME.TestCA,
					Logger:    certmagic.DefaultACME.Logger,
					HTTPProxy: certmagic.DefaultACME.HTTPProxy,
					DNS01Solver: &certmagic.DNS01Solver{
						DNSProvider: cmd.Notebrew.DNSProvider,
					},
				}),
			}
		} else {
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
					CA:        certmagic.DefaultACME.CA,
					TestCA:    certmagic.DefaultACME.TestCA,
					Logger:    certmagic.DefaultACME.Logger,
					HTTPProxy: certmagic.DefaultACME.HTTPProxy,
				}),
			}
		}
		err := staticCertConfig.ManageSync(context.Background(), cmd.Notebrew.ManagingDomains)
		if err != nil {
			return err
		}
		dynamicCertConfig := certmagic.NewDefault()
		dynamicCertConfig.Storage = cmd.Notebrew.CertStorage
		dynamicCertConfig.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				if certmagic.MatchWildcard(name, "*."+cmd.Notebrew.ContentDomain) {
					return nil
				}
				fileInfo, err := fs.Stat(cmd.Notebrew.FS.WithContext(ctx), name)
				if err != nil {
					return err
				}
				if !fileInfo.IsDir() {
					return fmt.Errorf("%q is not a directory", name)
				}
				return nil
			},
		}
		server.TLSConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if clientHello.ServerName == "" {
					return nil, fmt.Errorf("server name required")
				}
				for _, domain := range cmd.Notebrew.ManagingDomains {
					if certmagic.MatchWildcard(clientHello.ServerName, domain) {
						return staticCertConfig.GetCertificate(clientHello)
					}
				}
				return dynamicCertConfig.GetCertificate(clientHello)
			},
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
		}
		if cpuid.CPU.Supports(cpuid.AESNI) {
			server.TLSConfig.CipherSuites = []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			}
		}
	case 80:
		server.Addr = ":80"
		server.Handler = http.TimeoutHandler(cmd.Notebrew, 60*time.Second, "The server took too long to process your request.")
	default:
		if len(cmd.Notebrew.ProxyConfig.RealIPHeaders) == 0 && len(cmd.Notebrew.ProxyConfig.ProxyIPs) == 0 {
			server.Addr = "localhost:" + strconv.Itoa(cmd.Notebrew.Port)
		} else {
			server.Addr = ":" + strconv.Itoa(cmd.Notebrew.Port)
		}
		server.Handler = cmd.Notebrew
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
			if !cmd.Notebrew.CMSDomainHTTPS {
				fmt.Fprintln(cmd.Stdout, "notebrew is already running on http://"+cmd.Notebrew.CMSDomain+"/files/")
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
		if !cmd.Notebrew.CMSDomainHTTPS {
			fmt.Fprintf(cmd.Stdout, startmsg, "http://"+cmd.Notebrew.CMSDomain+"/files/")
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
