package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func Notebrew(configDir, dataDir string, args []string) (*nb10.Notebrew, error) {
	nbrew := nb10.New()
	nbrew.Logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	}))

	// CMS domain.
	b, err := os.ReadFile(filepath.Join(configDir, "cmsdomain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "cmsdomain.txt"), err)
	}
	nbrew.CMSDomain = string(bytes.TrimSpace(b))

	// Content domain.
	b, err = os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "contentdomain.txt"), err)
	}
	nbrew.ContentDomain = string(bytes.TrimSpace(b))

	// Img domain.
	b, err = os.ReadFile(filepath.Join(configDir, "imgdomain.txt"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "imgdomain.txt"), err)
		}
	} else {
		nbrew.ImgDomain = string(bytes.TrimSpace(b))
	}

	// Img cmd.
	b, err = os.ReadFile(filepath.Join(configDir, "imgcmd.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "imgcmd.txt"), err)
	}
	nbrew.ImgCmd = string(bytes.TrimSpace(b))

	// Port.
	b, err = os.ReadFile(filepath.Join(configDir, "port.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
	}
	port := string(bytes.TrimSpace(b))

	// Fill in the port and CMS domain if missing.
	if port != "" {
		nbrew.Port, err = strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a valid integer", filepath.Join(configDir, "port.txt"), port)
		}
		if nbrew.Port <= 0 {
			return nil, fmt.Errorf("%s: %d is not a valid port", filepath.Join(configDir, "port.txt"), nbrew.Port)
		}
		if nbrew.CMSDomain == "" {
			switch nbrew.Port {
			case 443:
				return nil, fmt.Errorf("%s: cannot use port 443 without specifying the cmsdomain", filepath.Join(configDir, "port.txt"))
			case 80:
				break // Use IP address as domain when we find it later.
			default:
				nbrew.CMSDomain = "localhost:" + port
			}
		}
	} else {
		if nbrew.CMSDomain != "" {
			nbrew.Port = 443
		} else {
			nbrew.Port = 6444
			nbrew.CMSDomain = "localhost:6444"
		}
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
			return nil, err
		}
		if !nbrew.IP4.IsValid() && !nbrew.IP6.IsValid() {
			return nil, fmt.Errorf("unable to determine the IP address of the current machine")
		}
		if nbrew.CMSDomain == "" {
			if nbrew.IP4.IsValid() {
				nbrew.CMSDomain = nbrew.IP4.String()
			} else {
				nbrew.CMSDomain = "[" + nbrew.IP6.String() + "]"
			}
		}
	}
	if nbrew.ContentDomain == "" {
		nbrew.ContentDomain = nbrew.CMSDomain
	}

	// DNS.
	b, err = os.ReadFile(filepath.Join(configDir, "dns.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
	}
	b = bytes.TrimSpace(b)
	var dnsConfig DNSConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&dnsConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
		}
	}
	switch dnsConfig.Provider {
	case "":
		break
	case "namecheap":
		if dnsConfig.Username == "" {
			return nil, fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configDir, "dns.json"))
		}
		if dnsConfig.APIKey == "" {
			return nil, fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configDir, "dns.json"))
		}
		if !nbrew.IP4.IsValid() && (nbrew.Port == 443 || nbrew.Port == 80) {
			return nil, fmt.Errorf("the current machine's IP address (%s) is not IPv4: an IPv4 address is needed to integrate with namecheap's API", nbrew.IP6.String())
		}
		nbrew.DNSProvider = &namecheap.Provider{
			APIKey:      dnsConfig.APIKey,
			User:        dnsConfig.Username,
			APIEndpoint: "https://api.namecheap.com/xml.response",
			ClientIP:    nbrew.IP4.String(),
		}
	case "cloudflare":
		if dnsConfig.APIToken == "" {
			return nil, fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &cloudflare.Provider{
			APIToken: dnsConfig.APIToken,
		}
	case "porkbun":
		if dnsConfig.APIKey == "" {
			return nil, fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configDir, "dns.json"))
		}
		if dnsConfig.SecretKey == "" {
			return nil, fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &porkbun.Provider{
			APIKey:       dnsConfig.APIKey,
			APISecretKey: dnsConfig.SecretKey,
		}
	case "godaddy":
		if dnsConfig.APIToken == "" {
			return nil, fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &godaddy.Provider{
			APIToken: dnsConfig.APIToken,
		}
	default:
		return nil, fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configDir, "dns.json"), dnsConfig.Provider)
	}

	_, err1 := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(nbrew.CMSDomain, "["), "]"))
	_, err2 := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(nbrew.ContentDomain, "["), "]"))
	cmsDomainIsIP := err1 == nil
	contentDomainIsIP := err2 == nil
	if !cmsDomainIsIP {
		nbrew.Domains = append(nbrew.Domains, nbrew.CMSDomain, "www."+nbrew.CMSDomain)
		nbrew.CMSDomainHTTPS = !strings.HasPrefix(nbrew.CMSDomain, "localhost:") && nbrew.Port != 80
	}
	if !contentDomainIsIP {
		if nbrew.ContentDomain == nbrew.CMSDomain {
			nbrew.Domains = append(nbrew.Domains, "img."+nbrew.ContentDomain)
			nbrew.ContentDomainHTTPS = nbrew.CMSDomainHTTPS
		} else {
			nbrew.Domains = append(nbrew.Domains, nbrew.ContentDomain, "www."+nbrew.ContentDomain, "img."+nbrew.ContentDomain)
			nbrew.ContentDomainHTTPS = !strings.HasPrefix(nbrew.ContentDomain, "localhost:")
		}
	}

	// Certmagic.
	b, err = os.ReadFile(filepath.Join(configDir, "certmagic.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "certmagic.txt"), err)
	}
	certmagicDir := string(bytes.TrimSpace(b))
	if certmagicDir == "" {
		certmagicDir = filepath.Join(configDir, "certmagic")
	} else {
		certmagicDir = filepath.Clean(certmagicDir)
	}
	err = os.MkdirAll(certmagicDir, 0755)
	if err != nil {
		return nil, err
	}
	nbrew.CertStorage = &certmagic.FileStorage{
		Path: certmagicDir,
	}

	if nbrew.Port == 443 || nbrew.Port == 80 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		group, groupctx := errgroup.WithContext(ctx)
		matched := make([]bool, len(nbrew.Domains))
		for i, domain := range nbrew.Domains {
			i, domain := i, domain
			group.Go(func() error {
				_, err := netip.ParseAddr(domain)
				if err == nil {
					return nil
				}
				ips, err := net.DefaultResolver.LookupIPAddr(groupctx, domain)
				if err != nil {
					fmt.Println(err)
					return nil
				}
				for _, ip := range ips {
					ip, ok := netip.AddrFromSlice(ip.IP)
					if !ok {
						continue
					}
					if ip.Is4() && ip == nbrew.IP4 || ip.Is6() && ip == nbrew.IP6 {
						matched[i] = true
						break
					}
				}
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			return nil, err
		}
		if nbrew.Port == 80 {
			for i, domain := range nbrew.Domains {
				if matched[i] {
					nbrew.ManagingDomains = append(nbrew.ManagingDomains, domain)
				}
			}
		} else if nbrew.Port == 443 {
			cmsDomainWildcard := "*." + nbrew.CMSDomain
			cmsDomainWildcardAdded := false
			contentDomainWildcard := "*." + nbrew.ContentDomain
			contentDomainWildcardAdded := false
			for i, domain := range nbrew.Domains {
				if matched[i] {
					if certmagic.MatchWildcard(domain, cmsDomainWildcard) && nbrew.DNSProvider != nil {
						if !cmsDomainWildcardAdded {
							cmsDomainWildcardAdded = true
							nbrew.ManagingDomains = append(nbrew.ManagingDomains, cmsDomainWildcard)
						}
					} else if certmagic.MatchWildcard(domain, contentDomainWildcard) && nbrew.DNSProvider != nil {
						if !contentDomainWildcardAdded {
							contentDomainWildcardAdded = true
							nbrew.ManagingDomains = append(nbrew.ManagingDomains, contentDomainWildcard)
						}
					} else {
						nbrew.ManagingDomains = append(nbrew.ManagingDomains, domain)
					}
				}
			}
		}
	}

	// Database.
	b, err = os.ReadFile(filepath.Join(configDir, "database.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
	}
	b = bytes.TrimSpace(b)
	var databaseConfig DatabaseConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&databaseConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
		}
	}
	if databaseConfig.Dialect != "" {
		var dataSourceName string
		switch databaseConfig.Dialect {
		case "sqlite":
			if databaseConfig.FilePath == "" {
				databaseConfig.FilePath = filepath.Join(dataDir, "notebrew-database.db")
			}
			databaseConfig.FilePath, err = filepath.Abs(databaseConfig.FilePath)
			if err != nil {
				return nil, fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "database.json"), err)
			}
			dataSourceName = databaseConfig.FilePath + "?" + sqliteQueryString(databaseConfig.Params)
			nbrew.Dialect = "sqlite"
			nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
			if err != nil {
				return nil, fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
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
				return nil, fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
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
				return nil, err
			}
			// Set user and passwd manually to accomodate special characters.
			// https://github.com/go-sql-driver/mysql/issues/1323
			config.User = databaseConfig.User
			config.Passwd = databaseConfig.Password
			driver, err := mysql.NewConnector(config)
			if err != nil {
				return nil, err
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
			return nil, fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "database.json"), databaseConfig.Dialect)
		}

		err := nbrew.DB.Ping()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "database.json"), nbrew.Dialect, dataSourceName, err)
		}
		databaseCatalog, err := nb10.DatabaseCatalog(nbrew.Dialect)
		if err != nil {
			return nil, err
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
			return nil, err
		}
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
				return nil, err
			}
		}
	}

	// Files.
	b, err = os.ReadFile(filepath.Join(configDir, "files.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
	}
	b = bytes.TrimSpace(b)
	var filesConfig DatabaseConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&filesConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
		}
	}
	if filesConfig.Dialect == "" {
		if filesConfig.FilePath == "" {
			filesConfig.FilePath = filepath.Join(dataDir, "notebrew-files")
		} else {
			filesConfig.FilePath = filepath.Clean(filesConfig.FilePath)
		}
		err := os.MkdirAll(filesConfig.FilePath, 0755)
		if err != nil {
			return nil, err
		}
		nbrew.FS, err = nb10.NewDirFS(nb10.DirFSConfig{
			RootDir: filesConfig.FilePath,
			TempDir: os.TempDir(),
		})
		if err != nil {
			return nil, err
		}
	} else {
		var dataSourceName string
		var dialect string
		var db *sql.DB
		var errorCode func(error) string
		switch filesConfig.Dialect {
		case "sqlite":
			if filesConfig.FilePath == "" {
				filesConfig.FilePath = filepath.Join(dataDir, "notebrew-files.db")
			}
			filesConfig.FilePath, err = filepath.Abs(filesConfig.FilePath)
			if err != nil {
				return nil, fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "files.json"), err)
			}
			dataSourceName = filesConfig.FilePath + "?" + sqliteQueryString(filesConfig.Params)
			dialect = "sqlite"
			db, err = sql.Open(sqliteDriverName, dataSourceName)
			if err != nil {
				return nil, fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
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
				return nil, fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
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
				return nil, err
			}
			// Set user and passwd manually to accomodate special characters.
			// https://github.com/go-sql-driver/mysql/issues/1323
			config.User = filesConfig.User
			config.Passwd = filesConfig.Password
			driver, err := mysql.NewConnector(config)
			if err != nil {
				return nil, err
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
			return nil, fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "files.json"), filesConfig.Dialect)
		}
		err = db.Ping()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "files.json"), dialect, dataSourceName, err)
		}
		filesCatalog, err := nb10.FilesCatalog(dialect)
		if err != nil {
			return nil, err
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
			return nil, err
		}
		if dialect == "sqlite" {
			dbi := ddl.NewDatabaseIntrospector(dialect, db)
			dbi.Tables = []string{"files_fts5"}
			tables, err := dbi.GetTables()
			if err != nil {
				return nil, err
			}
			if len(tables) == 0 {
				_, err := db.Exec("CREATE VIRTUAL TABLE files_fts5 USING fts5 (file_name, text, content = 'files');")
				if err != nil {
					return nil, err
				}
			}
			dbi.Tables = []string{"files"}
			triggers, err := dbi.GetTriggers()
			if err != nil {
				return nil, err
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
					return nil, err
				}
			}
			if _, ok := triggerNames["files_after_delete"]; !ok {
				_, err := db.Exec("CREATE TRIGGER files_after_delete AFTER DELETE ON files BEGIN" +
					"\n    INSERT INTO files_fts5 (files_fts5, rowid, file_name, text) VALUES ('delete', OLD.rowid, OLD.file_name, OLD.text);" +
					"\nEND;",
				)
				if err != nil {
					return nil, err
				}
			}
			if _, ok := triggerNames["files_after_update"]; !ok {
				_, err := db.Exec("CREATE TRIGGER files_after_update AFTER UPDATE ON files BEGIN" +
					"\n    INSERT INTO files_fts5 (files_fts5, rowid, file_name, text) VALUES ('delete', OLD.rowid, OLD.file_name, OLD.text);" +
					"\n    INSERT INTO files_fts5 (rowid, file_name, text) VALUES (NEW.rowid, NEW.file_name, NEW.text);" +
					"\nEND;",
				)
				if err != nil {
					return nil, err
				}
			}
		}

		// Objects.
		var objectStorage nb10.ObjectStorage
		b, err = os.ReadFile(filepath.Join(configDir, "objects.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "objects.json"), err)
		}
		b = bytes.TrimSpace(b)
		var objectsConfig ObjectsConfig
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&objectsConfig)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "objects.json"), err)
			}
		}
		switch objectsConfig.Provider {
		case "", "directory":
			if objectsConfig.FilePath == "" {
				objectsConfig.FilePath = filepath.Join(dataDir, "notebrew-objects")
			} else {
				objectsConfig.FilePath = filepath.Clean(objectsConfig.FilePath)
			}
			err := os.MkdirAll(objectsConfig.FilePath, 0755)
			if err != nil {
				return nil, err
			}
			objectStorage, err = nb10.NewDirObjectStorage(objectsConfig.FilePath, os.TempDir())
			if err != nil {
				return nil, err
			}
		case "s3":
			if objectsConfig.Endpoint == "" {
				return nil, fmt.Errorf("%s: missing endpoint field", filepath.Join(configDir, "objects.json"))
			}
			if objectsConfig.Region == "" {
				return nil, fmt.Errorf("%s: missing region field", filepath.Join(configDir, "objects.json"))
			}
			if objectsConfig.Bucket == "" {
				return nil, fmt.Errorf("%s: missing bucket field", filepath.Join(configDir, "objects.json"))
			}
			if objectsConfig.AccessKeyID == "" {
				return nil, fmt.Errorf("%s: missing accessKeyID field", filepath.Join(configDir, "objects.json"))
			}
			if objectsConfig.SecretAccessKey == "" {
				return nil, fmt.Errorf("%s: missing secretAccessKey field", filepath.Join(configDir, "objects.json"))
			}
			objectStorage, err = nb10.NewS3Storage(context.Background(), nb10.S3StorageConfig{
				Endpoint:        objectsConfig.Endpoint,
				Region:          objectsConfig.Region,
				Bucket:          objectsConfig.Bucket,
				AccessKeyID:     objectsConfig.AccessKeyID,
				SecretAccessKey: objectsConfig.SecretAccessKey,
				Logger:          nbrew.Logger,
			})
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%s: unsupported provider %q (possible values: directory, s3)", filepath.Join(configDir, "objects.json"), objectsConfig.Provider)
		}
		databaseFS, err := nb10.NewDatabaseFS(nb10.DatabaseFSConfig{
			DB:            db,
			Dialect:       dialect,
			ErrorCode:     errorCode,
			ObjectStorage: objectStorage,
			Logger:        nbrew.Logger,
		})
		if err != nil {
			return nil, err
		}
		if nbrew.DB != nil {
			databaseFS.UpdateStorageUsed = func(ctx context.Context, sitePrefix string, delta int64) error {
				if delta == 0 {
					return nil
				}
				_, err = sq.Exec(ctx, nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format: "UPDATE site" +
						" SET storage_used = CASE WHEN coalesce(storage_used, 0) + {delta} >= 0 THEN coalesce(storage_used, 0) + {delta} ELSE 0 END" +
						" WHERE site_name = {siteName}",
					Values: []any{
						sq.Int64Param("delta", delta),
						sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
					},
				})
				if err != nil {
					return err
				}
				return nil
			}
		}
		nbrew.FS = databaseFS
	}
	for _, dir := range []string{
		"notes",
		"pages",
		"posts",
		"output",
		"output/posts",
		"output/themes",
		"imports",
		"exports",
	} {
		err = nbrew.FS.Mkdir(dir, 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "site.json")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		tmpl, err := texttemplate.ParseFS(nb10.RuntimeFS, "embed/site.json")
		if err != nil {
			return nil, err
		}
		writer, err := nbrew.FS.OpenWriter("site.json", 0644)
		if err != nil {
			return nil, err
		}
		defer writer.Close()
		err = tmpl.Execute(writer, "home")
		if err != nil {
			return nil, err
		}
		err = writer.Close()
		if err != nil {
			return nil, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "posts/postlist.json")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/postlist.json")
		if err != nil {
			return nil, err
		}
		writer, err := nbrew.FS.OpenWriter("posts/postlist.json", 0644)
		if err != nil {
			return nil, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, err
		}
		err = writer.Close()
		if err != nil {
			return nil, err
		}
	}
	siteGen, err := nb10.NewSiteGenerator(context.Background(), nb10.SiteGeneratorConfig{
		FS:                 nbrew.FS,
		ContentDomain:      nbrew.ContentDomain,
		ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
		ImgDomain:          nbrew.ImgDomain,
		SitePrefix:         "",
	})
	if err != nil {
		return nil, err
	}
	_, err = fs.Stat(nbrew.FS, "pages/index.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/index.html")
		if err != nil {
			return nil, err
		}
		writer, err := nbrew.FS.OpenWriter("pages/index.html", 0644)
		if err != nil {
			return nil, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, err
		}
		err = writer.Close()
		if err != nil {
			return nil, err
		}
		err = siteGen.GeneratePage(context.Background(), "pages/index.html", string(b))
		if err != nil {
			return nil, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "pages/404.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/404.html")
		if err != nil {
			return nil, err
		}
		writer, err := nbrew.FS.OpenWriter("pages/404.html", 0644)
		if err != nil {
			return nil, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, err
		}
		err = writer.Close()
		if err != nil {
			return nil, err
		}
		err = siteGen.GeneratePage(context.Background(), "pages/404.html", string(b))
		if err != nil {
			return nil, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "posts/post.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/post.html")
		if err != nil {
			return nil, err
		}
		writer, err := nbrew.FS.OpenWriter("posts/post.html", 0644)
		if err != nil {
			return nil, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, err
		}
		err = writer.Close()
		if err != nil {
			return nil, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "posts/postlist.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/postlist.html")
		if err != nil {
			return nil, err
		}
		writer, err := nbrew.FS.OpenWriter("posts/postlist.html", 0644)
		if err != nil {
			return nil, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, err
		}
		err = writer.Close()
		if err != nil {
			return nil, err
		}
		tmpl, err := siteGen.PostListTemplate(context.Background(), "")
		if err != nil {
			return nil, err
		}
		_, err = siteGen.GeneratePostList(context.Background(), "", tmpl)
		if err != nil {
			return nil, err
		}
	}

	// Captcha.
	b, err = os.ReadFile(filepath.Join(configDir, "captcha.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var captchaConfig CaptchaConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&captchaConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
		}
		nbrew.CaptchaConfig.WidgetScriptSrc = template.URL(captchaConfig.WidgetScriptSrc)
		nbrew.CaptchaConfig.WidgetClass = captchaConfig.WidgetClass
		nbrew.CaptchaConfig.VerificationURL = captchaConfig.VerificationURL
		nbrew.CaptchaConfig.SiteKey = captchaConfig.SiteKey
		nbrew.CaptchaConfig.SecretKey = captchaConfig.SecretKey
		nbrew.CaptchaConfig.CSP = captchaConfig.CSP
	}

	// Proxy.
	b, err = os.ReadFile(filepath.Join(configDir, "proxy.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var proxyConfig ProxyConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&proxyConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
		}
		nbrew.ProxyConfig.RealIPHeaders = make(map[netip.Addr]string)
		for ip, header := range proxyConfig.RealIPHeaders {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("%s: realIPHeaders: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
			}
			nbrew.ProxyConfig.RealIPHeaders[addr] = header
		}
		nbrew.ProxyConfig.ProxyIPs = make(map[netip.Addr]struct{})
		for _, ip := range proxyConfig.ProxyIPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("%s: proxyIPs: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
			}
			nbrew.ProxyConfig.ProxyIPs[addr] = struct{}{}
		}
	}

	// Content Security Policy.
	var buf strings.Builder
	// default-src
	buf.WriteString("default-src 'none';")
	// script-src
	buf.WriteString(" script-src 'self' 'unsafe-hashes' " + nb10.BaselineJSHash)
	if value := nbrew.CaptchaConfig.CSP["script-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// connect-src
	buf.WriteString(" connect-src 'self'")
	if value := nbrew.CaptchaConfig.CSP["connect-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// img-src
	buf.WriteString(" img-src 'self' data:")
	if nbrew.ImgDomain != "" {
		buf.WriteString(" " + nbrew.ImgDomain)
	}
	buf.WriteString(";")
	// style-src
	buf.WriteString(" style-src 'self' 'unsafe-inline'")
	if value := nbrew.CaptchaConfig.CSP["style-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// base-uri
	buf.WriteString(" base-uri 'self';")
	// form-action
	buf.WriteString(" form-action 'self';")
	// manifest-src
	buf.WriteString(" manifest-src 'self';")
	// frame-src
	if value := nbrew.CaptchaConfig.CSP["frame-src"]; value != "" {
		buf.WriteString(" frame-src " + value + ";")
	}
	nbrew.ContentSecurityPolicy = buf.String()
	return nbrew, nil
}

func NewServer(nbrew *nb10.Notebrew) (*http.Server, error) {
	server := &http.Server{
		ErrorLog: log.New(&LogFilter{Stderr: os.Stderr}, "", log.LstdFlags),
	}
	switch nbrew.Port {
	case 443:
		server.Addr = ":443"
		server.Handler = nbrew
		server.ReadHeaderTimeout = 5 * time.Minute
		server.WriteTimeout = 60 * time.Minute
		server.IdleTimeout = 5 * time.Minute
		staticCertConfig := certmagic.NewDefault()
		staticCertConfig.Storage = nbrew.CertStorage
		if nbrew.DNSProvider != nil {
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
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
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
					CA:        certmagic.DefaultACME.CA,
					TestCA:    certmagic.DefaultACME.TestCA,
					Logger:    certmagic.DefaultACME.Logger,
					HTTPProxy: certmagic.DefaultACME.HTTPProxy,
				}),
			}
		}
		if len(nbrew.ManagingDomains) == 0 {
			fmt.Printf("WARNING: notebrew is listening on port 443 but no domains are pointing at this current machine's IP address (%s/%s). It means no traffic can reach this current machine. Please configure your DNS correctly.\n", nbrew.IP4.String(), nbrew.IP6.String())
		}
		err := staticCertConfig.ManageSync(context.Background(), nbrew.ManagingDomains)
		if err != nil {
			return nil, err
		}
		dynamicCertConfig := certmagic.NewDefault()
		dynamicCertConfig.Storage = nbrew.CertStorage
		dynamicCertConfig.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				var sitePrefix string
				if certmagic.MatchWildcard(name, "*."+nbrew.ContentDomain) {
					sitePrefix = "@" + strings.TrimSuffix(name, "."+nbrew.ContentDomain)
				} else {
					sitePrefix = name
				}
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(ctx), sitePrefix)
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
				for _, domain := range nbrew.ManagingDomains {
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
		server.Handler = nbrew
	default:
		if len(nbrew.ProxyConfig.RealIPHeaders) == 0 && len(nbrew.ProxyConfig.ProxyIPs) == 0 {
			server.Addr = "localhost:" + strconv.Itoa(nbrew.Port)
		} else {
			server.Addr = ":" + strconv.Itoa(nbrew.Port)
		}
		server.Handler = nbrew
	}
	return server, nil
}

type LogFilter struct {
	Stderr io.Writer
}

func (logFilter *LogFilter) Write(p []byte) (n int, err error) {
	if bytes.Contains(p, []byte("http: TLS handshake error from ")) {
		return 0, nil
	}
	return logFilter.Stderr.Write(p)
}
