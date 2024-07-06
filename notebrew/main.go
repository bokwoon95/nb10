package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/cli"
	"github.com/bokwoon95/nb10/sq"
	"github.com/bokwoon95/sqddl/ddl"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/blake2b"
)

var (
	openBrowser  = func(address string) {}
	startMessage = "Running on %s\n"
)

func main() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		exit(err)
	}
	configHomeDir := os.Getenv("XDG_CONFIG_HOME")
	if configHomeDir == "" {
		configHomeDir = homeDir
	}
	dataHomeDir := os.Getenv("XDG_DATA_HOME")
	if dataHomeDir == "" {
		dataHomeDir = homeDir
	}
	var configDir string
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.StringVar(&configDir, "configdir", "", "")
	err = flagset.Parse(os.Args[1:])
	if err != nil {
		exit(err)
	}
	args := flagset.Args()
	if configDir == "" {
		configDir = filepath.Join(configHomeDir, "notebrew-config")
	} else {
		configDir = filepath.Clean(configDir)
	}
	err = os.MkdirAll(configDir, 0755)
	if err != nil {
		exit(err)
	}
	configDir, err = filepath.Abs(filepath.FromSlash(configDir))
	if err != nil {
		exit(err)
	}
	if len(args) > 0 {
		switch args[0] {
		case "config":
			cmd, err := cli.ConfigCommand(configDir, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "hashpassword":
			cmd, err := cli.HashpasswordCommand(args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		}
	}
	nbrew, err := cli.Notebrew(configDir, dataHomeDir, args)
	if err != nil {
		var migrationErr *ddl.MigrationError
		if errors.As(err, &migrationErr) {
			fmt.Println(migrationErr.Filename)
			fmt.Println(migrationErr.Contents)
		}
		exit(err)
	}
	defer nbrew.Close()
	if nbrew.DB != nil && nbrew.Dialect == "sqlite" {
		_, err := nbrew.DB.ExecContext(context.Background(), "PRAGMA optimize(0x10002)")
		if err != nil {
			nbrew.Logger.Error(err.Error())
		}
		ticker := time.NewTicker(4 * time.Hour)
		defer ticker.Stop()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for {
				<-ticker.C
				_, err := nbrew.DB.ExecContext(ctx, "PRAGMA optimize")
				if err != nil {
					nbrew.Logger.Error(err.Error())
				}
			}
		}()
	}
	if databaseFS, ok := nbrew.FS.(*nb10.DatabaseFS); ok && databaseFS.Dialect == "sqlite" {
		_, err := databaseFS.DB.ExecContext(context.Background(), "PRAGMA optimize(0x10002)")
		if err != nil {
			nbrew.Logger.Error(err.Error())
		}
		ticker := time.NewTicker(4 * time.Hour)
		defer ticker.Stop()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for {
				<-ticker.C
				_, err := databaseFS.DB.ExecContext(ctx, "PRAGMA optimize")
				if err != nil {
					nbrew.Logger.Error(err.Error())
				}
			}
		}()
	}
	if len(args) > 0 {
		switch args[0] {
		case "createinvite":
			cmd, err := cli.CreateinviteCommand(nbrew, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "createsite":
			cmd, err := cli.CreatesiteCommand(nbrew, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "createuser":
			cmd, err := cli.CreateuserCommand(nbrew, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "deleteinvite":
			cmd, err := cli.DeleteinviteCommand(nbrew, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "deletesite":
			cmd, err := cli.DeletesiteCommand(nbrew, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "deleteuser":
			cmd, err := cli.DeleteuserCommand(nbrew, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "permissions":
			cmd, err := cli.PermissionsCommand(nbrew, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "resetpassword":
			cmd, err := cli.ResetpasswordCommand(nbrew, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "start":
			cmd, err := cli.StartCommand(nbrew, configDir, startMessage, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "status":
			cmd, err := cli.StatusCommand(nbrew, configDir, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		case "stop":
			cmd, err := cli.StopCommand(nbrew, configDir, args[1:]...)
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			err = cmd.Run()
			if err != nil {
				exit(fmt.Errorf("%s: %w", args[0], err))
			}
			return
		default:
			exit(fmt.Errorf("unknown command: %s", args[0]))
			return
		}
	}
	server, err := cli.NewServer(nbrew)
	if err != nil {
		exit(err)
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			exit(err)
		}
		// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
		const WSAEADDRINUSE = syscall.Errno(10048)
		if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
			if !nbrew.CMSDomainHTTPS {
				fmt.Println("notebrew is already running on http://" + nbrew.CMSDomain + "/files/")
				openBrowser("http://" + server.Addr + "/files/")
			} else {
				fmt.Println("notebrew is already running (run `notebrew stop` to stop the process)")
			}
			return
		}
		exit(err)
	}
	wait := make(chan os.Signal, 1)
	signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	if server.Addr == ":443" {
		fmt.Printf(startMessage, server.Addr)
		go func() {
			err := server.ServeTLS(listener, "", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Println(err)
				close(wait)
			}
		}()
		// Redirect HTTP to HTTPS.
		go http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" && r.Method != "HEAD" {
				http.Error(w, "Use HTTPS", http.StatusBadRequest)
				return
			}
			_ = r.ParseForm()
			// Don't redirect API calls from HTTP to HTTPS.
			// https://jviide.iki.fi/http-redirects
			if r.Host == nbrew.CMSDomain && r.Form.Has("api") {
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
					_, _ = sq.Exec(r.Context(), nbrew.DB, sq.Query{
						Dialect: nbrew.Dialect,
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
	} else {
		if !nbrew.CMSDomainHTTPS {
			fmt.Printf(startMessage, "http://"+nbrew.CMSDomain+"/files/")
			openBrowser("http://" + server.Addr + "/files/")
		} else {
			fmt.Printf(startMessage, server.Addr)
		}
		go func() {
			err := server.Serve(listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Println(err)
				close(wait)
			}
		}()
	}
	<-wait
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	server.Shutdown(ctx)
}
