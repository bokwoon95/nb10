package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/cli"
	"github.com/bokwoon95/nb10/sq"
	"github.com/bokwoon95/sqddl/ddl"
	"github.com/stripe/stripe-go/v79"
	"golang.org/x/crypto/blake2b"
)

var (
	openBrowser  = func(address string) {}
	startMessage = "Running on %s\n"
	exit         = func(exitErr error) {
		fmt.Println(exitErr)
		os.Exit(1)
	}
)

func main() {
	err := func() error {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
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
			return err
		}
		args := flagset.Args()
		if configDir == "" {
			configDir = filepath.Join(configHomeDir, "notebrew-config")
		} else {
			configDir = filepath.Clean(configDir)
		}
		err = os.MkdirAll(configDir, 0755)
		if err != nil {
			return err
		}
		configDir, err = filepath.Abs(filepath.FromSlash(configDir))
		if err != nil {
			return err
		}
		if len(args) > 0 {
			switch args[0] {
			case "config":
				cmd, err := cli.ConfigCommand(configDir, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "configx":
				cmd, err := ConfigxCommand(configDir, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "hashpassword":
				cmd, err := cli.HashpasswordCommand(args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			}
		}
		nbrew, closers, err := cli.Notebrew(configDir, dataHomeDir)
		defer func() {
			for i := len(closers) - 1; i >= 0; i-- {
				closers[i].Close()
			}
		}()
		if err != nil {
			return err
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
		nbrewx, err := NewNotebrewx(configDir, nbrew)
		if err != nil {
			return err
		}
		stripe.Key = nbrewx.StripeConfig.SecretKey
		if len(args) > 0 {
			switch args[0] {
			case "createinvite":
				cmd, err := cli.CreateinviteCommand(nbrew, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "createsite":
				cmd, err := cli.CreatesiteCommand(nbrew, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "createuser":
				cmd, err := cli.CreateuserCommand(nbrew, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "deleteinvite":
				cmd, err := cli.DeleteinviteCommand(nbrew, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "deletesite":
				cmd, err := cli.DeletesiteCommand(nbrew, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "deleteuser":
				cmd, err := cli.DeleteuserCommand(nbrew, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "permissions":
				cmd, err := cli.PermissionsCommand(nbrew, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "resetpassword":
				cmd, err := cli.ResetpasswordCommand(nbrew, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "start":
				cmd, err := cli.StartCommand(nbrew, configDir, startMessage, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				cmd.Handler = nbrewx
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "status":
				cmd, err := cli.StatusCommand(nbrew, configDir, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "stop":
				cmd, err := cli.StopCommand(nbrew, configDir, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				return nil
			case "version":
				fmt.Println(nb10.Version)
				return nil
			default:
				return fmt.Errorf("unknown command: %s", args[0])
			}
		}
		server, err := cli.NewServer(nbrew)
		if err != nil {
			return err
		}
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme := "https://"
			if r.TLS == nil {
				scheme = "http://"
			}
			// Redirect the www subdomain to the bare domain.
			if r.Host == "www."+nbrew.CMSDomain {
				http.Redirect(w, r, scheme+nbrew.CMSDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
				return
			}
			// Redirect unclean paths to the cleaned path equivalent.
			if r.Method == "GET" || r.Method == "HEAD" {
				cleanedPath := path.Clean(r.URL.Path)
				if cleanedPath != "/" {
					_, ok := nb10.AllowedFileTypes[path.Ext(cleanedPath)]
					if !ok {
						cleanedPath += "/"
					}
				}
				if cleanedPath != r.URL.Path {
					cleanedURL := *r.URL
					cleanedURL.Path = cleanedPath
					http.Redirect(w, r, cleanedURL.String(), http.StatusMovedPermanently)
					return
				}
			}
			r = r.WithContext(context.WithValue(r.Context(), nb10.LoggerKey, nbrew.Logger.With(
				slog.String("method", r.Method),
				slog.String("url", scheme+r.Host+r.URL.RequestURI()),
			)))
			nbrew.AddSecurityHeaders(w)
			if r.Host != nbrew.CMSDomain {
				nbrew.ServeHTTP(w, r)
				return
			}
			err := r.ParseForm()
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
			urlPath := strings.Trim(r.URL.Path, "/")
			head, tail, _ := strings.Cut(urlPath, "/")
			switch head {
			case "signup":
				switch tail {
				case "":
					nbrewx.signup(w, r)
					return
				case "success":
					nbrewx.signupSuccess(w, r)
					return
				}
			case "users":
				var user nb10.User
				var sessionToken string
				header := r.Header.Get("Authorization")
				if header != "" {
					if strings.HasPrefix(header, "Bearer ") {
						sessionToken = strings.TrimPrefix(header, "Bearer ")
					}
				} else {
					cookie, _ := r.Cookie("session")
					if cookie != nil {
						sessionToken = cookie.Value
					}
				}
				if sessionToken != "" {
					sessionTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", sessionToken))
					if err == nil && len(sessionTokenBytes) == 24 {
						var sessionTokenHash [8 + blake2b.Size256]byte
						checksum := blake2b.Sum256(sessionTokenBytes[8:])
						copy(sessionTokenHash[:8], sessionTokenBytes[:8])
						copy(sessionTokenHash[8:], checksum[:])
						user, err = sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
							Dialect: nbrew.Dialect,
							Format: "SELECT {*}" +
								" FROM session" +
								" JOIN users ON users.user_id = session.user_id" +
								" WHERE session.session_token_hash = {sessionTokenHash}",
							Values: []any{
								sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
							},
						}, func(row *sq.Row) nb10.User {
							return nb10.User{
								UserID:                row.UUID("users.user_id"),
								Username:              row.String("users.username"),
								Email:                 row.String("users.email"),
								TimezoneOffsetSeconds: row.Int("users.timezone_offset_seconds"),
								DisableReason:         row.String("users.disable_reason"),
								SiteLimit:             row.Int64("coalesce(users.site_limit, -1)"),
								StorageLimit:          row.Int64("coalesce(users.storage_limit, -1)"),
							}
						})
						if err != nil {
							if !errors.Is(err, sql.ErrNoRows) {
								nbrew.GetLogger(r.Context()).Error(err.Error())
								nbrew.InternalServerError(w, r, err)
								return
							}
						}
					}
				}
				switch tail {
				case "login":
					nbrew.Login(w, r, user, "/users/resetpassword/")
					return
				case "profile":
				case "resetpassword":
				case "billing":
				}
			}
			nbrew.ServeHTTP(w, r)
		})
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			var errno syscall.Errno
			if !errors.As(err, &errno) {
				return err
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
				return nil
			}
			return err
		}
		wait := make(chan os.Signal, 1)
		signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		if server.Addr == ":443" {
			go http.ListenAndServe(":80", http.HandlerFunc(nbrew.RedirectToHTTPS))
			go func() {
				err := server.ServeTLS(listener, "", "")
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			fmt.Printf(startMessage, server.Addr)
		} else {
			go func() {
				err := server.Serve(listener)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			if !nbrew.CMSDomainHTTPS {
				fmt.Printf(startMessage, "http://"+nbrew.CMSDomain+"/files/")
				openBrowser("http://" + server.Addr + "/files/")
			} else {
				fmt.Printf(startMessage, server.Addr)
			}
		}
		<-wait
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		server.Shutdown(ctx)
		return nil
	}()
	if err != nil {
		var migrationErr *ddl.MigrationError
		if errors.As(err, &migrationErr) {
			fmt.Println(migrationErr.Filename)
			fmt.Println(migrationErr.Contents)
		}
		exit(err)
	}
}
