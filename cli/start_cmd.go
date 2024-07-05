package cli

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
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
	"github.com/bokwoon95/nb10/sq"
	"github.com/caddyserver/certmagic"
	"github.com/klauspost/cpuid/v2"
	"golang.org/x/crypto/blake2b"
)

type StartCmd struct {
	Notebrew     *nb10.Notebrew
	Stdout       io.Writer
	ConfigDir    string
	StartMessage string
	Handler      http.Handler
}

func StartCommand(nbrew *nb10.Notebrew, configDir string, startMessage string, args ...string) (*StartCmd, error) {
	var cmd StartCmd
	cmd.Notebrew = nbrew
	cmd.ConfigDir = configDir
	cmd.StartMessage = startMessage
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
	if cmd.Handler == nil {
		cmd.Handler = cmd.Notebrew
	}
	server := http.Server{
		ErrorLog: log.New(&LogFilter{Stderr: os.Stderr}, "", log.LstdFlags),
	}
	switch cmd.Notebrew.Port {
	case 443:
		server.Addr = ":443"
		server.Handler = cmd.Handler
		server.ReadHeaderTimeout = 5 * time.Minute
		server.WriteTimeout = 60 * time.Minute
		server.IdleTimeout = 5 * time.Minute
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
		if len(cmd.Notebrew.ManagingDomains) == 0 {
			fmt.Fprintf(cmd.Stdout, "WARNING: notebrew is listening on port 443 but no domains are pointing at this current machine's IP address (%s/%s). It means no traffic can reach this current machine. Please configure your DNS correctly.\n", cmd.Notebrew.IP4.String(), cmd.Notebrew.IP6.String())
		}
		err := staticCertConfig.ManageSync(context.Background(), cmd.Notebrew.ManagingDomains)
		if err != nil {
			return err
		}
		dynamicCertConfig := certmagic.NewDefault()
		dynamicCertConfig.Storage = cmd.Notebrew.CertStorage
		dynamicCertConfig.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				var sitePrefix string
				if certmagic.MatchWildcard(name, "*."+cmd.Notebrew.ContentDomain) {
					sitePrefix = "@" + strings.TrimSuffix(name, "."+cmd.Notebrew.ContentDomain)
				} else {
					sitePrefix = name
				}
				fileInfo, err := fs.Stat(cmd.Notebrew.FS.WithContext(ctx), sitePrefix)
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
						certificate, err := staticCertConfig.GetCertificate(clientHello)
						if err != nil {
							return nil, err
						}
						return certificate, nil
					}
				}
				certificate, err := dynamicCertConfig.GetCertificate(clientHello)
				if err != nil {
					return nil, err
				}
				return certificate, nil
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
		server.Handler = cmd.Handler
	default:
		if len(cmd.Notebrew.ProxyConfig.RealIPHeaders) == 0 && len(cmd.Notebrew.ProxyConfig.ProxyIPs) == 0 {
			server.Addr = "localhost:" + strconv.Itoa(cmd.Notebrew.Port)
		} else {
			server.Addr = ":" + strconv.Itoa(cmd.Notebrew.Port)
		}
		server.Handler = cmd.Notebrew
	}

	// Manually acquire a listener instead of using ListenAndServe() so that we
	// can report back to the user if the port is already in use.
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return err
		}
		// WSAEADDRINUSE copied from
		// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
		// to avoid importing an entire 3rd party library just to use a constant.
		const WSAEADDRINUSE = syscall.Errno(10048)
		if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
			if !cmd.Notebrew.CMSDomainHTTPS {
				fmt.Fprintln(cmd.Stdout, "notebrew is already running on http://"+cmd.Notebrew.CMSDomain+"/files/")
			} else {
				fmt.Fprintln(cmd.Stdout, "notebrew is already running (run `notebrew stop` to stop the process)")
			}
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
	signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	if server.Addr == ":443" {
		go func() {
			err := server.ServeTLS(listener, "", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Println(err)
				close(wait)
			}
		}()
		go http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" && r.Method != "HEAD" {
				http.Error(w, "Use HTTPS", http.StatusBadRequest)
				return
			}
			_ = r.ParseForm()
			// Don't redirect API calls from HTTP to HTTPS.
			// https://jviide.iki.fi/http-redirects
			if r.Host == cmd.Notebrew.CMSDomain && r.Form.Has("api") {
				var authenticationTokenHashes [][]byte
				header := r.Header.Get("Authorization")
				if header != "" {
					authenticationToken, err := hex.DecodeString(fmt.Sprintf("%048s", strings.TrimPrefix(header, "Notebrew ")))
					if err == nil {
						var authenticationTokenHash [8 + blake2b.Size256]byte
						checksum := blake2b.Sum256(authenticationToken[8:])
						copy(authenticationTokenHash[:8], authenticationToken[:8])
						copy(authenticationTokenHash[8:], checksum[:])
						authenticationTokenHashes = append(authenticationTokenHashes, authenticationTokenHash[:])
					}
				}
				cookie, _ := r.Cookie("authentication")
				if cookie != nil && cookie.Value != "" {
					authenticationToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
					if err == nil {
						var authenticationTokenHash [8 + blake2b.Size256]byte
						checksum := blake2b.Sum256(authenticationToken[8:])
						copy(authenticationTokenHash[:8], authenticationToken[:8])
						copy(authenticationTokenHash[8:], checksum[:])
						authenticationTokenHashes = append(authenticationTokenHashes, authenticationTokenHash[:])
					}
				}
				if len(authenticationTokenHashes) > 0 {
					_, _ = sq.Exec(r.Context(), cmd.Notebrew.DB, sq.Query{
						Dialect: cmd.Notebrew.Dialect,
						Format:  "DELETE FROM authentication WHERE authentication_token_hash IN ({authenticationTokenHashes})",
						Values: []any{
							sq.Param("authenticationTokenHashes", authenticationTokenHashes),
						},
					})
				}
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
		fmt.Printf(cmd.StartMessage, server.Addr)
	} else {
		go func() {
			err := server.Serve(listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Println(err)
				close(wait)
			}
		}()
		if !cmd.Notebrew.CMSDomainHTTPS {
			fmt.Printf(cmd.StartMessage, "http://"+cmd.Notebrew.CMSDomain+"/files/")
		} else {
			fmt.Printf(cmd.StartMessage, server.Addr)
		}
	}
	<-wait
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	server.Shutdown(ctx)
	return nil
}
