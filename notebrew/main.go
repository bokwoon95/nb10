package main

import (
	"bytes"
	"context"
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
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
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

		// Port.
		b, err := os.ReadFile(filepath.Join(configDir, "port.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
		}
		port := string(bytes.TrimSpace(b))
		if port != "" {
			_, err = strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("%s: %q is not a valid integer", filepath.Join(configDir, "port.txt"), port)
			}
		}

		// CMS domain.
		b, err = os.ReadFile(filepath.Join(configDir, "cmsdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "cmsdomain.txt"), err)
		}
		nbrew.CMSDomain = string(bytes.TrimSpace(b))

		// Determine the TCP address to listen on (based on the CMS domain and port).
		var addr string
		if port != "" {
			if nbrew.CMSDomain == "" {
				nbrew.CMSDomain = "localhost:" + port
			}
			if port == "443" || port == "80" {
				addr = ":" + port
			} else {
				addr = "localhost:" + port
			}
		} else {
			if nbrew.CMSDomain == "" {
				nbrew.CMSDomain = "localhost:6444"
				addr = "localhost:6444"
			} else {
				addr = ":443"
			}
		}

		// Content domain.
		b, err = os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "contentdomain.txt"), err)
		}
		nbrew.ContentDomain = string(bytes.TrimSpace(b))
		if nbrew.ContentDomain == "" {
			nbrew.ContentDomain = nbrew.CMSDomain
		}

		// Img domain.
		b, err = os.ReadFile(filepath.Join(configDir, "imgdomain.txt"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "imgdomain.txt"), err)
			}
		} else {
			nbrew.ImgDomain = string(bytes.TrimSpace(b))
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
							ctx, cancel := context.WithTimeout(context.Background(), time.Second)
							_, err = nbrew.DB.ExecContext(ctx, "PRAGMA analysis_limit(400); PRAGMA optimize;")
							if err != nil {
								nbrew.Logger.Error(err.Error())
							}
							cancel()
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
							ctx, cancel := context.WithTimeout(context.Background(), time.Second)
							_, err = db.ExecContext(ctx, "PRAGMA analysis_limit(400); PRAGMA optimize;")
							if err != nil {
								nbrew.Logger.Error(err.Error())
							}
							cancel()
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
				cmd, err := StartCommand(nbrew, configDir, addr, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "status":
				cmd, err := StatusCommand(nbrew, configDir, addr, commandArgs...)
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("%s: %w", command, err)
				}
			case "stop":
				cmd, err := StopCommand(nbrew, configDir, addr, commandArgs...)
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

		server, err := NewServer(nbrew, configDir, addr)
		if err != nil {
			return err
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
				// TODO: don't assume notebrew is already running, in this path SIGHUP will end the process so the server is unlikely to be running
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
