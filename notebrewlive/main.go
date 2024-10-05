package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/cli"
	"github.com/bokwoon95/nb10/sq"
	"github.com/bokwoon95/nb10/stacktrace"
	"github.com/bokwoon95/sqddl/ddl"
	"github.com/stripe/stripe-go/v79"
	"golang.org/x/crypto/blake2b"
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
		nbrew, closers, err := cli.Notebrew(configDir, dataHomeDir, map[string]string{
			"connect-src": "https://*.stripe.com/",
			"frame-src":   "https://*.stripe.com/",
			"script-src":  "https://*.stripe.com/",
			"img-src":     "https://*.stripe.com/",
			"form-action": "https://*.stripe.com/",
		})
		defer func() {
			for i := len(closers) - 1; i >= 0; i-- {
				closers[i].Close()
			}
		}()
		if err != nil {
			return err
		}
		defer nbrew.Close()
		if nbrew.DB != nil {
			databaseCatalog, err := nb10.UnmarshalCatalog(nbrew.Dialect, databaseSchemaBytes)
			if err != nil {
				return err
			}
			automigrateCmd := &ddl.AutomigrateCmd{
				DB:             nbrew.DB,
				Dialect:        nbrew.Dialect,
				DestCatalog:    databaseCatalog,
				AcceptWarnings: true,
				Stderr:         io.Discard,
			}
			err = automigrateCmd.Run()
			if err != nil {
				return err
			}
		}
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
		// Stripe.
		var stripeConfig StripeConfig
		b, err := os.ReadFile(filepath.Join(configDir, "stripe.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "stripe.json"), err)
		}
		b = bytes.TrimSpace(b)
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&stripeConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "stripe.json"), err)
			}
			stripe.Key = stripeConfig.SecretKey
		}
		// Signup.
		b, err = os.ReadFile(filepath.Join(configDir, "signupdisabled.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "signupdisabled.txt"), err)
		}
		signupDisabled, _ := strconv.ParseBool(string(bytes.TrimSpace(b)))
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
				cmd, err := cli.StartCommand(nbrew, configDir, args[1:]...)
				if err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				cmd.Handler = ServeHTTP(nbrew, stripeConfig, signupDisabled)
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
		server.Handler = ServeHTTP(nbrew, stripeConfig, signupDisabled)
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
			fmt.Printf("notebrew is running on %s\n", server.Addr)
		} else {
			go func() {
				err := server.Serve(listener)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			if !nbrew.CMSDomainHTTPS {
				fmt.Printf("notebrew is running on %s\n", "http://"+nbrew.CMSDomain+"/files/")
			} else {
				fmt.Printf("notebrew is running on %s\n", server.Addr)
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
		fmt.Println(err)
		os.Exit(1)
	}
}

func ServeHTTP(nbrew *nb10.Notebrew, stripeConfig StripeConfig, signupDisabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		nbrew.AddSecurityHeaders(w)
		r = r.WithContext(context.WithValue(r.Context(), nb10.LoggerKey, nbrew.Logger.With(
			slog.String("method", r.Method),
			slog.String("url", scheme+r.Host+r.URL.RequestURI()),
		)))
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
		switch urlPath {
		case "users/profile":
			if nbrew.DB == nil {
				nbrew.NotFound(w, r)
				return
			}
			cookie, _ := r.Cookie("session")
			if cookie == nil || cookie.Value == "" {
				nbrew.NotAuthenticated(w, r)
				return
			}
			sessionTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
			if err != nil || len(sessionTokenBytes) != 24 {
				nbrew.NotAuthenticated(w, r)
				return
			}
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionTokenBytes[8:])
			copy(sessionTokenHash[:8], sessionTokenBytes[:8])
			copy(sessionTokenHash[8:], checksum[:])
			user, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM session" +
					" JOIN users ON users.user_id = session.user_id" +
					" LEFT JOIN customer ON customer.user_id = session.user_id" +
					" WHERE session.session_token_hash = {sessionTokenHash}",
				Values: []any{
					sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
				},
			}, func(row *sq.Row) User {
				var user User
				user.UserID = row.UUID("users.user_id")
				user.Username = row.String("users.username")
				user.Email = row.String("users.email")
				user.TimezoneOffsetSeconds = row.Int("users.timezone_offset_seconds")
				user.DisableReason = row.String("users.disable_reason")
				user.SiteLimit = row.Int64("coalesce(users.site_limit, -1)")
				user.StorageLimit = row.Int64("coalesce(users.storage_limit, -1)")
				b := row.Bytes(nil, "users.user_flags")
				if len(b) > 0 {
					err := json.Unmarshal(b, &user.UserFlags)
					if err != nil {
						panic(stacktrace.New(err))
					}
				}
				user.CustomerID = row.String("customer.customer_id")
				return user
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					nbrew.NotAuthenticated(w, r)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			profile(nbrew, w, r, user, stripeConfig)
			return
		case "stripe/webhook":
			if nbrew.DB == nil {
				nbrew.NotFound(w, r)
				return
			}
			stripeWebhook(nbrew, w, r, stripeConfig)
			return
		}
		head, tail, _ := strings.Cut(urlPath, "/")
		switch head {
		case "signup":
			if nbrew.DB == nil || nbrew.Mailer == nil || signupDisabled {
				nbrew.NotFound(w, r)
				return
			}
			switch tail {
			case "":
				signup(nbrew, w, r)
				return
			case "success":
				signupSuccess(nbrew, w, r)
				return
			}
		case "stripe":
			if nbrew.DB == nil {
				nbrew.NotFound(w, r)
				return
			}
			cookie, _ := r.Cookie("session")
			if cookie == nil || cookie.Value == "" {
				nbrew.NotAuthenticated(w, r)
				return
			}
			sessionTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
			if err != nil || len(sessionTokenBytes) != 24 {
				nbrew.NotAuthenticated(w, r)
				return
			}
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionTokenBytes[8:])
			copy(sessionTokenHash[:8], sessionTokenBytes[:8])
			copy(sessionTokenHash[8:], checksum[:])
			user, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM session" +
					" JOIN users ON users.user_id = session.user_id" +
					" LEFT JOIN customer ON customer.user_id = session.user_id" +
					" WHERE session.session_token_hash = {sessionTokenHash}",
				Values: []any{
					sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
				},
			}, func(row *sq.Row) User {
				var user User
				user.UserID = row.UUID("users.user_id")
				user.Username = row.String("users.username")
				user.Email = row.String("users.email")
				user.TimezoneOffsetSeconds = row.Int("users.timezone_offset_seconds")
				user.DisableReason = row.String("users.disable_reason")
				user.SiteLimit = row.Int64("coalesce(users.site_limit, -1)")
				user.StorageLimit = row.Int64("coalesce(users.storage_limit, -1)")
				b := row.Bytes(nil, "users.user_flags")
				if len(b) > 0 {
					err := json.Unmarshal(b, &user.UserFlags)
					if err != nil {
						panic(stacktrace.New(err))
					}
				}
				user.CustomerID = row.String("customer.customer_id")
				return user
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					nbrew.NotAuthenticated(w, r)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			switch tail {
			case "checkout":
				stripeCheckout(nbrew, w, r, user, stripeConfig)
				return
			case "checkout/success":
				stripeCheckoutSuccess(nbrew, w, r, user, stripeConfig)
				return
			case "portal":
				stripePortal(nbrew, w, r, user)
				return
			}
		}
		nbrew.ServeHTTP(w, r)
	}
}
