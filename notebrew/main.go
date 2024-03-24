package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	texttemplate "text/template"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
	"github.com/bokwoon95/sqddl/ddl"
	"github.com/caddyserver/certmagic"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/klauspost/cpuid/v2"
	"github.com/libdns/cloudflare"
	"github.com/libdns/godaddy"
	"github.com/libdns/namecheap"
	"github.com/libdns/porkbun"
	"golang.org/x/sync/errgroup"
)

type SMTPConfig struct {
	Username string
	Password string
	Host     string
	Port     string
}

var (
	open     = func(address string) {}
	startmsg = "Running on %s\n"
)

// static/dynamic private/public config:
// - static private: users.json, dns.json, s3.json, smtp.json (excluded)
// - static public: files.txt cmsdomain.txt, contentdomain.txt, multisite.txt
// - dynamic private: captcha.json
// port.txt cmsdomain.txt contentdomain.txt imgdomain.txt database.json files.json objects.json captcha.json dns.json certmagic.txt

func main() {
	// Wrap main in anonymous function to honor deferred calls.
	// https://stackoverflow.com/questions/27629380/how-to-exit-a-go-program-honoring-deferred-calls
	err := func() error {
		// homeDir is the user's home directory.
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		// configHomeDir is the user's config directory.
		configHomeDir := os.Getenv("XDG_CONFIG_HOME")
		if configHomeDir == "" {
			configHomeDir = homeDir
		}
		// dataHomeDir is the user's data directory.
		dataHomeDir := os.Getenv("XDG_DATA_HOME")
		if dataHomeDir == "" {
			dataHomeDir = homeDir
		}
		// configDir is notebrew's configuration directory.
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
			err := os.MkdirAll(configDir, 0755)
			if err != nil {
				return err
			}
		} else {
			configDir = filepath.Clean(configDir)
			_, err := os.Stat(configDir)
			if err != nil {
				return err
			}
		}
		configDir, err = filepath.Abs(filepath.FromSlash(configDir))
		if err != nil {
			return err
		}
		if len(args) > 0 && args[0] == "config" {
			cmd, err := ConfigCommand(configDir, args[1:]...)
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			err = cmd.Run()
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			return nil
		}
		nbrew := &nb10.Notebrew{
			Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				AddSource: true,
			})),
		}

		// CMS domain.
		b, err := os.ReadFile(filepath.Join(configDir, "cmsdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "cmsdomain.txt"), err)
		}
		nbrew.CMSDomain = string(bytes.TrimSpace(b))

		// Content domain.
		b, err = os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "contentdomain.txt"), err)
		}
		nbrew.ContentDomain = string(bytes.TrimSpace(b))

		// Img domain.
		b, err = os.ReadFile(filepath.Join(configDir, "imgdomain.txt"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "imgdomain.txt"), err)
			}
		} else {
			nbrew.ImgDomain = string(bytes.TrimSpace(b))
		}

		// Port.
		b, err = os.ReadFile(filepath.Join(configDir, "port.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
		}
		port := string(bytes.TrimSpace(b))

		// Fill in the port and CMS domain if missing.
		if port != "" {
			nbrew.Port, err = strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("%s: %q is not a valid integer", filepath.Join(configDir, "port.txt"), port)
			}
			if nbrew.Port <= 0 {
				return fmt.Errorf("%s: %d is not a valid port", filepath.Join(configDir, "port.txt"), nbrew.Port)
			}
			if nbrew.CMSDomain == "" {
				nbrew.CMSDomain = "localhost:" + port
			}
		} else {
			if nbrew.CMSDomain == "" {
				nbrew.Port = 6444
				nbrew.CMSDomain = "localhost:6444"
			} else {
				nbrew.Port = 443
			}
		}
		if nbrew.ContentDomain == "" {
			nbrew.ContentDomain = nbrew.CMSDomain
		}
		if nbrew.Port == 443 || nbrew.Port == 80 {
			// IP4 and IP6.
			client := &http.Client{
				Timeout: 10 * time.Second,
			}
			group, groupctx := errgroup.WithContext(context.Background())
			group.Go(func() error {
				request, err := http.NewRequest("GET", "https://ipv4.icanhazip.com", nil)
				if err != nil {
					return fmt.Errorf("ipv4.icanhazip.com: %w", err)
				}
				response, err := client.Do(request.WithContext(groupctx))
				if err != nil {
					return fmt.Errorf("ipv4.icanhazip.com: %w", err)
				}
				defer response.Body.Close()
				var b strings.Builder
				_, err = io.Copy(&b, response.Body)
				if err != nil {
					return fmt.Errorf("ipv4.icanhazip.com: %w", err)
				}
				err = response.Body.Close()
				if err != nil {
					return err
				}
				s := strings.TrimSpace(b.String())
				if s == "" {
					return nil
				}
				ip, err := netip.ParseAddr(s)
				if err != nil {
					return fmt.Errorf("ipv4.icanhazip.com: did not get a valid IP address (%s)", s)
				}
				if ip.Is4() {
					nbrew.IP4 = ip
				}
				return nil
			})
			group.Go(func() error {
				request, err := http.NewRequest("GET", "https://ipv6.icanhazip.com", nil)
				if err != nil {
					return fmt.Errorf("ipv6.icanhazip.com: %w", err)
				}
				response, err := client.Do(request.WithContext(groupctx))
				if err != nil {
					return fmt.Errorf("ipv6.icanhazip.com: %w", err)
				}
				defer response.Body.Close()
				var b strings.Builder
				_, err = io.Copy(&b, response.Body)
				if err != nil {
					return fmt.Errorf("ipv6.icanhazip.com: %w", err)
				}
				err = response.Body.Close()
				if err != nil {
					return err
				}
				s := strings.TrimSpace(b.String())
				if s == "" {
					return nil
				}
				ip, err := netip.ParseAddr(s)
				if err != nil {
					return fmt.Errorf("ipv6.icanhazip.com: did not get a valid IP address (%s)", s)
				}
				if ip.Is6() {
					nbrew.IP6 = ip
				}
				return nil
			})
			err := group.Wait()
			if err != nil {
				return err
			}
			if !nbrew.IP4.IsValid() && !nbrew.IP6.IsValid() {
				return fmt.Errorf("unable to determine the IP address of the current machine")
			}
			if nbrew.Port == 443 {
				// DNS.
				b, err := os.ReadFile(filepath.Join(configDir, "dns.json"))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
				}
				b = bytes.TrimSpace(b)
				if len(b) > 0 {
					var dnsConfig struct {
						Provider  string
						Username  string
						APIKey    string
						APIToken  string
						SecretKey string
					}
					decoder := json.NewDecoder(bytes.NewReader(b))
					decoder.DisallowUnknownFields()
					err := decoder.Decode(&dnsConfig)
					if err != nil {
						return fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
					}
					switch dnsConfig.Provider {
					case "namecheap":
						if dnsConfig.Username == "" {
							return fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configDir, "dns.json"))
						}
						if dnsConfig.APIKey == "" {
							return fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configDir, "dns.json"))
						}
						if !nbrew.IP4.IsValid() {
							return fmt.Errorf("the current machine's IP address (%s) is not IPv4: an IPv4 address is needed to integrate with namecheap's API", nbrew.IP6.String())
						}
						nbrew.DNSProvider = &namecheap.Provider{
							APIKey:      dnsConfig.APIKey,
							User:        dnsConfig.Username,
							APIEndpoint: "https://api.namecheap.com/xml.response",
							ClientIP:    nbrew.IP4.String(),
						}
					case "cloudflare":
						if dnsConfig.APIToken == "" {
							return fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configDir, "dns.json"))
						}
						nbrew.DNSProvider = &cloudflare.Provider{
							APIToken: dnsConfig.APIToken,
						}
					case "porkbun":
						if dnsConfig.APIKey == "" {
							return fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configDir, "dns.json"))
						}
						if dnsConfig.SecretKey == "" {
							return fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configDir, "dns.json"))
						}
						nbrew.DNSProvider = &porkbun.Provider{
							APIKey:       dnsConfig.APIKey,
							APISecretKey: dnsConfig.SecretKey,
						}
					case "godaddy":
						if dnsConfig.APIToken == "" {
							return fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configDir, "dns.json"))
						}
						nbrew.DNSProvider = &godaddy.Provider{
							APIToken: dnsConfig.APIToken,
						}
					case "":
						return fmt.Errorf("%s: missing provider field", filepath.Join(configDir, "dns.json"))
					default:
						return fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configDir, "dns.json"), dnsConfig.Provider)
					}
				}

				// Certmagic.
				b, err = os.ReadFile(filepath.Join(configDir, "certmagic.txt"))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("%s: %w", filepath.Join(configDir, "certmagic.txt"), err)
				}
				certmagicDir := string(bytes.TrimSpace(b))
				if certmagicDir == "" {
					certmagicDir = filepath.Join(configDir, "certmagic")
					err := os.MkdirAll(certmagicDir, 0755)
					if err != nil {
						return err
					}
				} else {
					certmagicDir = filepath.Clean(certmagicDir)
					_, err := os.Stat(certmagicDir)
					if err != nil {
						return err
					}
				}
				// staticCertConfig manages the certificate for the main domain, content domain
				// and wildcard subdomain.
				nbrew.StaticCertConfig = certmagic.NewDefault()
				nbrew.StaticCertConfig.Storage = &certmagic.FileStorage{Path: certmagicDir}
				if nbrew.DNSProvider != nil {
					nbrew.StaticCertConfig.Issuers = []certmagic.Issuer{
						certmagic.NewACMEIssuer(nbrew.StaticCertConfig, certmagic.ACMEIssuer{
							CA:        certmagic.DefaultACME.CA,
							TestCA:    certmagic.DefaultACME.TestCA,
							Logger:    certmagic.DefaultACME.Logger,
							HTTPProxy: certmagic.DefaultACME.HTTPProxy,
							DNS01Solver: &certmagic.DNS01Solver{
								DNSProvider: nbrew.DNSProvider,
							},
						}),
					}
				} else {
					nbrew.StaticCertConfig.Issuers = []certmagic.Issuer{
						certmagic.NewACMEIssuer(nbrew.StaticCertConfig, certmagic.ACMEIssuer{
							CA:        certmagic.DefaultACME.CA,
							TestCA:    certmagic.DefaultACME.TestCA,
							Logger:    certmagic.DefaultACME.Logger,
							HTTPProxy: certmagic.DefaultACME.HTTPProxy,
						}),
					}
				}
				nbrew.DynamicCertConfig = certmagic.NewDefault()
				nbrew.DynamicCertConfig.Storage = &certmagic.FileStorage{Path: certmagicDir}
				nbrew.DynamicCertConfig.OnDemand = &certmagic.OnDemandConfig{
					DecisionFunc: func(ctx context.Context, name string) error {
						if certmagic.MatchWildcard(name, "*."+nbrew.ContentDomain) {
							return nil
						}
						fileInfo, err := fs.Stat(nbrew.FS.WithContext(ctx), name)
						if err != nil {
							return err
						}
						if !fileInfo.IsDir() {
							return fmt.Errorf("%q is not a directory", name)
						}
						return nil
					},
				}
				nbrew.TLSConfig = &tls.Config{
					NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
					GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
						if clientHello.ServerName == "" {
							return nil, fmt.Errorf("server name required")
						}
						for _, domain := range nbrew.StaticDomains {
							if strings.HasPrefix(domain, "*.") {
								if certmagic.MatchWildcard(clientHello.ServerName, domain) {
									return nbrew.StaticCertConfig.GetCertificate(clientHello)
								}
							} else {
								if clientHello.ServerName == domain {
									return nbrew.StaticCertConfig.GetCertificate(clientHello)
								}
							}
						}
						return nbrew.DynamicCertConfig.GetCertificate(clientHello)
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
					nbrew.TLSConfig.CipherSuites = []uint16{
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					}
				}

				if nbrew.CMSDomain == nbrew.ContentDomain {
					if nbrew.DNSProvider != nil {
						nbrew.StaticDomains = []string{nbrew.CMSDomain, "*." + nbrew.CMSDomain}
					} else {
						nbrew.StaticDomains = []string{nbrew.CMSDomain, "img." + nbrew.CMSDomain, "www." + nbrew.CMSDomain}
					}
				} else {
					if nbrew.DNSProvider != nil {
						nbrew.StaticDomains = []string{nbrew.ContentDomain, "*." + nbrew.ContentDomain, nbrew.CMSDomain, "*." + nbrew.CMSDomain}
					} else {
						nbrew.StaticDomains = []string{nbrew.ContentDomain, "img." + nbrew.ContentDomain, nbrew.CMSDomain, "www." + nbrew.CMSDomain, "www." + nbrew.ContentDomain}
					}
				}
			}
		}

		// Database.
		b, err = os.ReadFile(filepath.Join(configDir, "database.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
		}
		b = bytes.TrimSpace(b)
		var databaseConfig DatabaseConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&databaseConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
			}
		}
		if databaseConfig.Dialect != "" {
			var dataSourceName string
			switch databaseConfig.Dialect {
			case "sqlite":
				if databaseConfig.FilePath == "" {
					databaseConfig.FilePath = filepath.Join(dataHomeDir, "notebrew-database.db")
				}
				databaseConfig.FilePath, err = filepath.Abs(databaseConfig.FilePath)
				if err != nil {
					return fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "database.json"), err)
				}
				dataSourceName = databaseConfig.FilePath + "?" + sqliteQueryString(databaseConfig.Params)
				nbrew.Dialect = "sqlite"
				nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
				}
				nbrew.ErrorCode = sqliteErrorCode
			case "postgres":
				values := make(url.Values)
				for key, value := range databaseConfig.Params {
					switch key {
					case "sslmode":
						values.Set(key, value)
					}
				}
				if _, ok := databaseConfig.Params["sslmode"]; !ok {
					values.Set("sslmode", "disable")
				}
				if databaseConfig.Port == "" {
					databaseConfig.Port = "5432"
				}
				uri := url.URL{
					Scheme:   "postgres",
					User:     url.UserPassword(databaseConfig.User, databaseConfig.Password),
					Host:     databaseConfig.Host + ":" + databaseConfig.Port,
					Path:     databaseConfig.DBName,
					RawQuery: values.Encode(),
				}
				dataSourceName = uri.String()
				nbrew.Dialect = "postgres"
				nbrew.DB, err = sql.Open("pgx", dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
				}
				nbrew.ErrorCode = func(err error) string {
					var pgErr *pgconn.PgError
					if errors.As(err, &pgErr) {
						return pgErr.Code
					}
					return ""
				}
			case "mysql":
				values := make(url.Values)
				for key, value := range databaseConfig.Params {
					switch key {
					case "charset", "collation", "loc", "maxAllowedPacket",
						"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
						"tls", "writeTimeout", "connectionAttributes":
						values.Set(key, value)
					}
				}
				values.Set("multiStatements", "true")
				values.Set("parseTime", "true")
				if databaseConfig.Port == "" {
					databaseConfig.Port = "3306"
				}
				config, err := mysql.ParseDSN(fmt.Sprintf("tcp(%s:%s)/%s?%s", databaseConfig.Host, databaseConfig.Port, url.PathEscape(databaseConfig.DBName), values.Encode()))
				if err != nil {
					return err
				}
				// Set user and passwd manually to accomodate special characters.
				// https://github.com/go-sql-driver/mysql/issues/1323
				config.User = databaseConfig.User
				config.Passwd = databaseConfig.Password
				driver, err := mysql.NewConnector(config)
				if err != nil {
					return err
				}
				dataSourceName = config.FormatDSN()
				nbrew.Dialect = "mysql"
				nbrew.DB = sql.OpenDB(driver)
				nbrew.ErrorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
			default:
				return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "database.json"), databaseConfig.Dialect)
			}

			err := nbrew.DB.Ping()
			if err != nil {
				return fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "database.json"), nbrew.Dialect, dataSourceName, err)
			}
			databaseCatalog, err := nb10.DatabaseCatalog(nbrew.Dialect)
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
			defer func() {
				if nbrew.Dialect == "sqlite" {
					nbrew.DB.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
					ticker := time.NewTicker(4 * time.Hour)
					go func() {
						for {
							<-ticker.C
							nbrew.DB.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
						}
					}()
				}
				nbrew.DB.Close()
			}()
			_, err = sq.Exec(context.Background(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "INSERT INTO site (site_id, site_name) VALUES ({siteID}, '')",
				Values: []any{
					sq.UUIDParam("siteID", nb10.NewID()),
				},
			})
			if err != nil {
				errorCode := nbrew.ErrorCode(err)
				if !nb10.IsKeyViolation(nbrew.Dialect, errorCode) {
					return err
				}
			}
		}

		// Files.
		b, err = os.ReadFile(filepath.Join(configDir, "files.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
		}
		b = bytes.TrimSpace(b)
		var filesConfig DatabaseConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&filesConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
			}
		}
		if filesConfig.Dialect == "" {
			if filesConfig.FilePath == "" {
				filesConfig.FilePath = filepath.Join(dataHomeDir, "notebrew-files")
				err := os.MkdirAll(filesConfig.FilePath, 0755)
				if err != nil {
					return err
				}
			} else {
				filesConfig.FilePath = filepath.Clean(filesConfig.FilePath)
				_, err := os.Stat(filesConfig.FilePath)
				if err != nil {
					return err
				}
			}
			nbrew.FS, err = nb10.NewLocalFS(nb10.LocalFSConfig{
				RootDir: filesConfig.FilePath,
				TempDir: os.TempDir(),
			})
			if err != nil {
				return err
			}
		} else {
			var dataSourceName string
			var dialect string
			var db *sql.DB
			var errorCode func(error) string
			switch filesConfig.Dialect {
			case "sqlite":
				if filesConfig.FilePath == "" {
					filesConfig.FilePath = filepath.Join(dataHomeDir, "notebrew-files.db")
				}
				filesConfig.FilePath, err = filepath.Abs(filesConfig.FilePath)
				if err != nil {
					return fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "files.json"), err)
				}
				dataSourceName = filesConfig.FilePath + "?" + sqliteQueryString(filesConfig.Params)
				dialect = "sqlite"
				db, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
				}
				errorCode = sqliteErrorCode
			case "postgres":
				values := make(url.Values)
				for key, value := range filesConfig.Params {
					switch key {
					case "sslmode":
						values.Set(key, value)
					}
				}
				if _, ok := filesConfig.Params["sslmode"]; !ok {
					values.Set("sslmode", "disable")
				}
				if filesConfig.Port == "" {
					filesConfig.Port = "5432"
				}
				uri := url.URL{
					Scheme:   "postgres",
					User:     url.UserPassword(filesConfig.User, filesConfig.Password),
					Host:     filesConfig.Host + ":" + filesConfig.Port,
					Path:     filesConfig.DBName,
					RawQuery: values.Encode(),
				}
				dataSourceName = uri.String()
				dialect = "postgres"
				db, err = sql.Open("pgx", dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
				}
				errorCode = func(err error) string {
					var pgErr *pgconn.PgError
					if errors.As(err, &pgErr) {
						return pgErr.Code
					}
					return ""
				}
			case "mysql":
				values := make(url.Values)
				for key, value := range filesConfig.Params {
					switch key {
					case "charset", "collation", "loc", "maxAllowedPacket",
						"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
						"tls", "writeTimeout", "connectionAttributes":
						values.Set(key, value)
					}
				}
				values.Set("multiStatements", "true")
				values.Set("parseTime", "true")
				if filesConfig.Port == "" {
					filesConfig.Port = "3306"
				}
				config, err := mysql.ParseDSN(fmt.Sprintf("tcp(%s:%s)/%s?%s", filesConfig.Host, filesConfig.Port, url.PathEscape(filesConfig.DBName), values.Encode()))
				if err != nil {
					return err
				}
				// Set user and passwd manually to accomodate special characters.
				// https://github.com/go-sql-driver/mysql/issues/1323
				config.User = filesConfig.User
				config.Passwd = filesConfig.Password
				driver, err := mysql.NewConnector(config)
				if err != nil {
					return err
				}
				dataSourceName = config.FormatDSN()
				dialect = "mysql"
				db = sql.OpenDB(driver)
				errorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
			default:
				return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "files.json"), filesConfig.Dialect)
			}
			err = db.Ping()
			if err != nil {
				return fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "files.json"), dialect, dataSourceName, err)
			}
			filesCatalog, err := nb10.FilesCatalog(dialect)
			if err != nil {
				return err
			}
			automigrateCmd := &ddl.AutomigrateCmd{
				DB:             db,
				Dialect:        dialect,
				DestCatalog:    filesCatalog,
				AcceptWarnings: true,
				Stderr:         io.Discard,
			}
			err = automigrateCmd.Run()
			if err != nil {
				return err
			}
			if dialect == "sqlite" {
				dbi := ddl.NewDatabaseIntrospector(dialect, db)
				dbi.Tables = []string{"files_fts5"}
				tables, err := dbi.GetTables()
				if err != nil {
					return err
				}
				if len(tables) == 0 {
					_, err := db.Exec("CREATE VIRTUAL TABLE files_fts5 USING fts5 (file_name, text, content=files);")
					if err != nil {
						return err
					}
				}
				dbi.Tables = []string{"files"}
				triggers, err := dbi.GetTriggers()
				if err != nil {
					return err
				}
				triggerNames := make(map[string]struct{})
				for _, trigger := range triggers {
					triggerNames[trigger.TriggerName] = struct{}{}
				}
				if _, ok := triggerNames["files_after_insert"]; !ok {
					_, err := db.Exec("CREATE TRIGGER files_after_insert AFTER INSERT ON files BEGIN" +
						"\n    INSERT INTO files_fts5 (rowid, file_name, text) VALUES (NEW.rowid, NEW.file_name, NEW.text);" +
						"\nEND;",
					)
					if err != nil {
						return err
					}
				}
				if _, ok := triggerNames["files_after_delete"]; !ok {
					_, err := db.Exec("CREATE TRIGGER files_after_delete AFTER DELETE ON files BEGIN" +
						"\n    INSERT INTO files_fts5 (files_fts5, rowid, file_name, text) VALUES ('delete', OLD.rowid, OLD.file_name, OLD.text);" +
						"\nEND;",
					)
					if err != nil {
						return err
					}
				}
				if _, ok := triggerNames["files_after_update"]; !ok {
					_, err := db.Exec("CREATE TRIGGER files_after_update AFTER UPDATE ON files BEGIN" +
						"\n    INSERT INTO files_fts5 (files_fts5, rowid, file_name, text) VALUES ('delete', OLD.rowid, OLD.file_name, OLD.text);" +
						"\n    INSERT INTO files_fts5 (rowid, file_name, text) VALUES (NEW.rowid, NEW.file_name, NEW.text);" +
						"\nEND;",
					)
					if err != nil {
						return err
					}
				}
			}
			defer func() {
				if dialect == "sqlite" {
					db.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
					ticker := time.NewTicker(4 * time.Hour)
					go func() {
						for {
							<-ticker.C
							db.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
						}
					}()
				}
				db.Close()
			}()

			// Objects.
			var objectStorage nb10.ObjectStorage
			b, err = os.ReadFile(filepath.Join(configDir, "objects.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "objects.json"), err)
			}
			b = bytes.TrimSpace(b)
			var objectsConfig ObjectsConfig
			if len(b) > 0 {
				decoder := json.NewDecoder(bytes.NewReader(b))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&objectsConfig)
				if err != nil {
					return fmt.Errorf("%s: %w", filepath.Join(configDir, "objects.json"), err)
				}
			}
			switch objectsConfig.Provider {
			case "", "local":
				if objectsConfig.FilePath == "" {
					objectsConfig.FilePath = filepath.Join(dataHomeDir, "notebrew-objects")
					err := os.MkdirAll(objectsConfig.FilePath, 0755)
					if err != nil {
						return err
					}
				} else {
					objectsConfig.FilePath = filepath.Clean(objectsConfig.FilePath)
					_, err := os.Stat(objectsConfig.FilePath)
					if err != nil {
						return err
					}
				}
				objectStorage, err = nb10.NewLocalObjectStorage(objectsConfig.FilePath, os.TempDir())
				if err != nil {
					return err
				}
			case "s3":
				if objectsConfig.Endpoint == "" {
					return fmt.Errorf("%s: missing endpoint field", filepath.Join(configDir, "objects.json"))
				}
				if objectsConfig.Region == "" {
					return fmt.Errorf("%s: missing region field", filepath.Join(configDir, "objects.json"))
				}
				if objectsConfig.Bucket == "" {
					return fmt.Errorf("%s: missing bucket field", filepath.Join(configDir, "objects.json"))
				}
				if objectsConfig.AccessKeyID == "" {
					return fmt.Errorf("%s: missing accessKeyID field", filepath.Join(configDir, "objects.json"))
				}
				if objectsConfig.SecretAccessKey == "" {
					return fmt.Errorf("%s: missing secretAccessKey field", filepath.Join(configDir, "objects.json"))
				}
				objectStorage, err = nb10.NewS3Storage(context.Background(), nb10.S3StorageConfig{
					Endpoint:        objectsConfig.Endpoint,
					Region:          objectsConfig.Region,
					Bucket:          objectsConfig.Bucket,
					AccessKeyID:     objectsConfig.AccessKeyID,
					SecretAccessKey: objectsConfig.SecretAccessKey,
				})
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("%s: unsupported provider %q (possible values: local, s3)", filepath.Join(configDir, "objects.json"), objectsConfig.Provider)
			}
			nbrew.FS, err = nb10.NewDatabaseFS(nb10.DatabaseFSConfig{
				DB:            db,
				Dialect:       dialect,
				ErrorCode:     errorCode,
				ObjectStorage: objectStorage,
				Logger:        nbrew.Logger,
			})
			if err != nil {
				return err
			}
		}
		for _, dir := range []string{
			"notes",
			"output",
			"output/posts",
			"output/themes",
			"pages",
			"posts",
		} {
			err = nbrew.FS.Mkdir(dir, 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		}
		_, err = fs.Stat(nbrew.FS, "site.json")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			tmpl, err := texttemplate.ParseFS(nb10.RuntimeFS, "embed/site.json")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("site.json", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			err = tmpl.Execute(writer, "home")
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
		}
		_, err = fs.Stat(nbrew.FS, "posts/postlist.json")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			b, err := fs.ReadFile(nb10.RuntimeFS, "embed/postlist.json")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("posts/postlist.json", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
		}
		siteGen, err := nb10.NewSiteGenerator(context.Background(), nbrew.FS, "", nbrew.ContentDomain, nbrew.ImgDomain)
		if err != nil {
			return err
		}
		_, err = fs.Stat(nbrew.FS, "pages/index.html")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			b, err := fs.ReadFile(nb10.RuntimeFS, "embed/index.html")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("pages/index.html", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			err = siteGen.GeneratePage(context.Background(), "pages/index.html", string(b))
			if err != nil {
				return err
			}
		}
		_, err = fs.Stat(nbrew.FS, "pages/404.html")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			b, err := fs.ReadFile(nb10.RuntimeFS, "embed/404.html")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("pages/404.html", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			err = siteGen.GeneratePage(context.Background(), "pages/404.html", string(b))
			if err != nil {
				return err
			}
		}
		_, err = fs.Stat(nbrew.FS, "posts/post.html")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			b, err := fs.ReadFile(nb10.RuntimeFS, "embed/post.html")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("posts/post.html", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
		}
		_, err = fs.Stat(nbrew.FS, "posts/postlist.html")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			b, err := fs.ReadFile(nb10.RuntimeFS, "embed/postlist.html")
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.OpenWriter("posts/postlist.html", 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			tmpl, err := siteGen.PostListTemplate(context.Background(), "")
			if err != nil {
				return err
			}
			_, err = siteGen.GeneratePostList(context.Background(), "", tmpl)
			if err != nil {
				return err
			}
		}

		// Captcha.
		b, err = os.ReadFile(filepath.Join(configDir, "captcha.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
		}
		b = bytes.TrimSpace(b)
		if len(b) > 0 {
			var captchaConfig CaptchaConfig
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&captchaConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
			}
			nbrew.CaptchaConfig.WidgetScriptSrc = template.URL(captchaConfig.WidgetScriptSrc)
			nbrew.CaptchaConfig.WidgetClass = captchaConfig.WidgetClass
			nbrew.CaptchaConfig.VerificationURL = captchaConfig.VerificationURL
			nbrew.CaptchaConfig.SiteKey = captchaConfig.SiteKey
			nbrew.CaptchaConfig.SecretKey = captchaConfig.SecretKey
		}

		// Proxy.
		b, err = os.ReadFile(filepath.Join(configDir, "proxy.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
		}
		b = bytes.TrimSpace(b)
		if len(b) > 0 {
			var proxyConfig ProxyConfig
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&proxyConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
			}
			nbrew.ProxyConfig.RealIPHeaders = make(map[netip.Addr]string)
			for ip, header := range proxyConfig.RealIPHeaders {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					return fmt.Errorf("%s: realIPHeaders: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
				}
				nbrew.ProxyConfig.RealIPHeaders[addr] = header
			}
			nbrew.ProxyConfig.ProxyIPs = make(map[netip.Addr]struct{})
			for _, ip := range proxyConfig.ProxyIPs {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					return fmt.Errorf("%s: proxyIPs: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
				}
				nbrew.ProxyConfig.ProxyIPs[addr] = struct{}{}
			}
		}

		// TODO:
		// go install github.com/bokwoon95/notebrew/notebrew
		// irm github.com/bokwoon95/notebrew/install.cmd | iex
		// curl github.com/bokwoon95/notebrew/install.sh | sh

		if len(args) > 0 {
			command, commandArgs := args[0], args[1:]
			switch command {
			case "createinvite":
				cmd, err := CreateinviteCommand(nbrew, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "createsite":
				cmd, err := CreatesiteCommand(nbrew, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "createuser":
				cmd, err := CreateuserCommand(nbrew, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "deleteinvite":
				cmd, err := DeleteinviteCommand(nbrew, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "deletesite":
				cmd, err := DeletesiteCommand(nbrew, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "deleteuser":
				cmd, err := DeleteuserCommand(nbrew, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "hashpassword":
				cmd, err := HashpasswordCommand(commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "permissions":
				cmd, err := PermissionsCommand(nbrew, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "resetpassword":
				cmd, err := ResetpasswordCommand(nbrew, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "start":
				cmd, err := StartCommand(nbrew, configDir, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "status":
				cmd, err := StatusCommand(nbrew, configDir, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "stop":
				cmd, err := StopCommand(nbrew, configDir, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			default:
				return fmt.Errorf("unknown command: %s", command)
			}
			return nil
		}

		var server http.Server
		switch nbrew.Port {
		case 443:
			server.Addr = ":443"
			server.Handler = http.TimeoutHandler(nbrew, 60*time.Second, "The server took too long to process your request.")
			server.TLSConfig = nbrew.TLSConfig
			server.ReadTimeout = 60 * time.Second
			server.WriteTimeout = 60 * time.Second
			server.IdleTimeout = 120 * time.Second
			if nbrew.DNSProvider != nil {
				// TODO: check if the necessary DNS records have been set for
				// each of the static domains and if not, set them.
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				group, groupctx := errgroup.WithContext(ctx)
				resolved := make([]bool, len(nbrew.StaticDomains))
				for i, domain := range nbrew.StaticDomains {
					i, domain := i, domain
					group.Go(func() error {
						ips, err := net.DefaultResolver.LookupIPAddr(groupctx, domain)
						if err != nil {
							return err
						}
						for _, ip := range ips {
							ip, ok := netip.AddrFromSlice(ip.IP)
							if !ok {
								continue
							}
							if ip.Is4() && ip == nbrew.IP4 || ip.Is6() && ip == nbrew.IP6 {
								resolved[i] = true
								break
							}
						}
						return nil
					})
				}
				err := group.Wait()
				if err != nil {
					return err
				}
				var unresolvedDomains []string
				for i, domain := range nbrew.StaticDomains {
					if !resolved[i] {
						unresolvedDomains = append(unresolvedDomains, domain)
					}
				}
				if len(unresolvedDomains) > 0 {
					ips := make([]string, 0, 2)
					if nbrew.IP4.IsValid() {
						ips = append(ips, nbrew.IP4.String())
					}
					if nbrew.IP6.IsValid() {
						ips = append(ips, nbrew.IP6.String())
					}
					return fmt.Errorf("the following domains do not resolve the the current machine's IP address (%s): %s", strings.Join(ips, " or "), strings.Join(unresolvedDomains, ", "))
				}
			}
			err := nbrew.StaticCertConfig.ManageSync(context.Background(), nbrew.StaticDomains)
			if err != nil {
				return err
			}
		case 80:
			server.Addr = ":80"
			server.Handler = http.TimeoutHandler(nbrew, 60*time.Second, "The server took too long to process your request.")
		default:
			server.Addr = "localhost:" + strconv.Itoa(nbrew.Port)
			server.Handler = nbrew
		}

		// Manually acquire a listener instead of using the more convenient
		// ListenAndServe() just so that we can report back to the user if the
		// port is already in use.
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			var errno syscall.Errno
			if !errors.As(err, &errno) {
				return err
			}
			// WSAEADDRINUSE copied from
			// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
			// To avoid importing an entire 3rd party library just to use a constant.
			const WSAEADDRINUSE = syscall.Errno(10048)
			if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
				if server.Addr == "localhost" || strings.HasPrefix(server.Addr, "localhost:") {
					fmt.Println("notebrew is already running on http://" + server.Addr + "/files/")
					open("http://" + server.Addr + "/files/")
					return nil
				}
				fmt.Println("notebrew is already running (run `notebrew stop` to stop the process)")
				return nil
			}
			return err
		}

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
				host, _, err := net.SplitHostPort(r.Host)
				if err != nil {
					host = r.Host
				} else {
					host = net.JoinHostPort(host, "443")
				}
				http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
			}))
			fmt.Printf(startmsg, server.Addr)
		} else {
			go func() {
				err := server.Serve(listener)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			if server.Addr == "localhost" || strings.HasPrefix(server.Addr, "localhost:") {
				fmt.Printf(startmsg, "http://"+server.Addr+"/files/")
				open("http://" + server.Addr + "/files/")
			} else {
				fmt.Printf(startmsg, server.Addr)
			}
		}
		<-wait
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		server.Shutdown(ctx)
		return nil
	}()
	if err != nil && !errors.Is(err, flag.ErrHelp) && !errors.Is(err, io.EOF) {
		var migrationErr *ddl.MigrationError
		if errors.As(err, &migrationErr) {
			fmt.Println(err)
			fmt.Println(migrationErr.Filename)
			fmt.Println(migrationErr.Contents)
		} else {
			fmt.Println(err)
		}
		pressAnyKeyToExit()
		os.Exit(1)
	}
}
