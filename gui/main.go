package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/sqddl/ddl"
	"modernc.org/sqlite"
)

func main() {
	var gui GUI
	gui.App = app.New()
	gui.Window = gui.App.NewWindow("Notebrew")
	gui.Window.Resize(fyne.NewSize(300, 300))
	gui.Window.CenterOnScreen()
	gui.StartServer = make(chan struct{})
	gui.StopServer = make(chan struct{})
	gui.SyncDone = make(chan struct{})
	err := func() error {
		baseCtx, baseCtxCancel := context.WithCancel(context.Background())
		defer baseCtxCancel()
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		configDir := filepath.Join(homeDir, "notebrew-config")
		b, err := os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		contentDomain := string(bytes.TrimSpace(b))
		if contentDomain == "" {
			contentDomain = "example.com"
		}
		// Logger.
		logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			AddSource: true,
		})
		gui.Logger = slog.New(logHandler).With(slog.String("version", nb10.Version))
		// DatabaseFS.
		db, err := sql.Open("sqlite", filepath.Join(homeDir, "notebrew-files.db")+
			"?_pragma=busy_timeout(10000)"+
			"&_pragma=foreign_keys(ON)"+
			"&_pragma=journal_mode(WAL)"+
			"&_pragma=synchronous(NORMAL)"+
			"&_pragma=page_size(8192)"+
			"&_txlock=immediate",
		)
		if err != nil {
			return err
		}
		err = db.Ping()
		if err != nil {
			return err
		}
		filesCatalog, err := nb10.FilesCatalog("sqlite")
		if err != nil {
			return err
		}
		automigrateCmd := &ddl.AutomigrateCmd{
			DB:             db,
			Dialect:        "sqlite",
			DestCatalog:    filesCatalog,
			AcceptWarnings: true,
			Stderr:         io.Discard,
		}
		err = automigrateCmd.Run()
		if err != nil {
			return err
		}
		dbi := ddl.NewDatabaseIntrospector("sqlite", db)
		dbi.Tables = []string{"files_fts5"}
		tables, err := dbi.GetTables()
		if err != nil {
			return err
		}
		if len(tables) == 0 {
			_, err := db.Exec("CREATE VIRTUAL TABLE files_fts5 USING fts5 (file_name, text, content = 'files');")
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
		objectsFilePath := filepath.Join(homeDir, "notebrew-objects")
		err = os.MkdirAll(objectsFilePath, 0755)
		if err != nil {
			return err
		}
		dirObjectStorage, err := nb10.NewDirObjectStorage(objectsFilePath, os.TempDir())
		if err != nil {
			return err
		}
		gui.DatabaseFS, err = nb10.NewDatabaseFS(nb10.DatabaseFSConfig{
			DB:      db,
			Dialect: "sqlite",
			ErrorCode: func(err error) string {
				var sqliteErr *sqlite.Error
				if errors.As(err, &sqliteErr) {
					return strconv.Itoa(int(sqliteErr.Code()))
				}
				return ""
			},
			ObjectStorage: dirObjectStorage,
			Logger:        gui.Logger,
		})
		if err != nil {
			return err
		}
		// DirectoryFS.
		filesFilePath := filepath.Join(homeDir, "notebrew-files")
		err = os.MkdirAll(filesFilePath, 0755)
		if err != nil {
			return err
		}
		gui.DirectoryFS, err = nb10.NewDirectoryFS(nb10.DirectoryFSConfig{
			RootDir: filesFilePath,
		})
		if err != nil {
			return err
		}
		// Widgets.
		gui.ContentDomainLabel = widget.NewLabel("Site URL (used in RSS feed):")
		gui.ContentDomainEntry = widget.NewEntry()
		gui.ContentDomainEntry.SetPlaceHolder("your site URL e.g. example.com")
		gui.ContentDomainEntry.SetText(contentDomain)
		gui.StartButton = widget.NewButton("Start notebrew ▶", func() {
			pid, err := portPID(6444)
			if err != nil {
				dialog.ShowError(err, gui.Window)
				return
			}
			if pid > 0 {
				switch runtime.GOOS {
				case "linux":
					exec.Command("xdg-open", "https://localhost:6444").Start()
				case "windows":
					exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", "https://localhost:6444").Start()
				case "darwin":
					exec.Command("open", "https://localhost:6444").Start()
				}
				return
			}
			contentDomain := gui.ContentDomainEntry.Text
			go func() {
				err := os.MkdirAll(configDir, 0755)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
				err = os.WriteFile(filepath.Join(configDir, "contentdomain.txt"), []byte(contentDomain), 0644)
				if err != nil {
					dialog.ShowError(err, gui.Window)
					return
				}
			}()
			select {
			case gui.StartServer <- struct{}{}:
			default:
			}
		})
		gui.StopButton = widget.NewButton("Stop notebrew 🛑", func() {
			select {
			case gui.StopServer <- struct{}{}:
			default:
			}
		})
		gui.StopButton.Disable()
		gui.OpenBrowserButton = widget.NewButton("Open browser 🌐", func() {
			switch runtime.GOOS {
			case "linux":
				exec.Command("xdg-open", "https://localhost:6444").Start()
			case "windows":
				exec.Command("explorer.exe", "https://localhost:6444").Start()
			case "darwin":
				exec.Command("open", "https://localhost:6444").Start()
			}
		})
		gui.OpenBrowserButton.Disable()
		gui.OpenFolderButton = widget.NewButton("Open folder 📂", func() {
			switch runtime.GOOS {
			case "linux":
				exec.Command("xdg-open", filepath.Join(homeDir, "notebrew-files")).Start()
			case "windows":
				exec.Command("explorer.exe", filepath.Join(homeDir, "notebrew-files")).Start()
			case "darwin":
				exec.Command("open", filepath.Join(homeDir, "notebrew-files")).Start()
			}
		})
		gui.SyncButton = widget.NewButton("Sync folder 🔄", func() {
			if gui.SyncInProgress.Load() {
				// TODO: dispatch a StopSync event.
				if cancel := gui.SyncCancel.Load(); cancel != nil {
					(*cancel)()
				}
				<-gui.SyncDone
			} else {
				// TODO: dispatch a StartSync event.
				syncCtx, syncCancel := context.WithCancel(baseCtx)
				gui.SyncCancel.Store(&syncCancel)
				go gui.SyncFolder(syncCtx)
				gui.SyncButton.SetText("Stop sync ❌")
				gui.SyncProgressBar.Show()
			}
		})
		gui.SyncProgressBar = widget.NewProgressBar()
		gui.SyncProgressBar.Hide()
		gui.Window.SetContent(container.NewVBox(
			gui.ContentDomainLabel,
			gui.ContentDomainEntry,
			container.NewGridWithColumns(2, gui.StartButton, gui.StopButton),
			gui.OpenBrowserButton,
			gui.OpenFolderButton,
			gui.SyncButton,
			gui.SyncProgressBar,
		))
		go gui.ServerLoop()
		gui.Window.ShowAndRun()
		return nil
	}()
	if err != nil {
		gui.Window.SetTitle("Error starting notebrew")
		gui.Window.Resize(fyne.NewSize(300, 300))
		gui.Window.SetContent(widget.NewLabel(err.Error()))
		gui.Window.ShowAndRun()
		os.Exit(1)
	}
}

type GUI struct {
	App                fyne.App
	Window             fyne.Window
	Logger             *slog.Logger
	DatabaseFS         *nb10.DatabaseFS
	DirectoryFS        *nb10.DirectoryFS
	StartServer        chan struct{}
	StopServer         chan struct{}
	StartSync          chan struct{}
	StopSync           chan struct{}
	SyncInProgress     atomic.Bool
	SyncCancel         atomic.Pointer[context.CancelFunc]
	SyncDone           chan struct{}
	ContentDomainLabel *widget.Label
	ContentDomainEntry *widget.Entry
	StartButton        *widget.Button
	StopButton         *widget.Button
	OpenBrowserButton  *widget.Button
	OpenFolderButton   *widget.Button
	SyncButton         *widget.Button
	SyncProgressBar    *widget.ProgressBar
}

func (gui *GUI) ServerLoop() {
	// nbrew, closers, server live here.
	for {
		select {
		case <-gui.StartServer:
			gui.StartButton.Disable()
			gui.StopButton.Enable()
			gui.OpenBrowserButton.Enable()
		case <-gui.StopServer:
			gui.StartButton.Enable()
			gui.StopButton.Disable()
			gui.OpenBrowserButton.Disable()
		}
	}
}

func (gui *GUI) SyncLoop() {
	// syncCtx, syncCtxCancel live here.
	for {
		select {
		case <-gui.StartSync:
		case <-gui.StopSync:
		}
	}
}

func (gui *GUI) StartServer2(homeDir string, contentDomain string) error {
	var nbrew *nb10.Notebrew
	var closers []io.Closer
	var databaseFS *nb10.DatabaseFS
	var directoryFS *nb10.DirectoryFS
	var server *http.Server
	defer func() {
		gui.DatabaseFS = databaseFS
		gui.DirectoryFS = directoryFS
	}()
	nbrew = nb10.New()
	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	})
	nbrew.Logger = slog.New(logHandler).With(slog.String("version", nb10.Version))
	nbrew.CMSDomain = "localhost:6444"
	nbrew.ContentDomain = contentDomain
	nbrew.ContentDomainHTTPS = true
	nbrew.Port = 6444
	// DatabaseFS.
	db, err := sql.Open("sqlite", filepath.Join(homeDir, "notebrew-files.db")+
		"?_pragma=busy_timeout(10000)"+
		"&_pragma=foreign_keys(ON)"+
		"&_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(NORMAL)"+
		"&_pragma=page_size(8192)"+
		"&_txlock=immediate",
	)
	if err != nil {
		return err
	}
	err = db.Ping()
	if err != nil {
		return err
	}
	filesCatalog, err := nb10.FilesCatalog("sqlite")
	if err != nil {
		return err
	}
	automigrateCmd := &ddl.AutomigrateCmd{
		DB:             db,
		Dialect:        "sqlite",
		DestCatalog:    filesCatalog,
		AcceptWarnings: true,
		Stderr:         io.Discard,
	}
	err = automigrateCmd.Run()
	if err != nil {
		return err
	}
	dbi := ddl.NewDatabaseIntrospector("sqlite", db)
	dbi.Tables = []string{"files_fts5"}
	tables, err := dbi.GetTables()
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		_, err := db.Exec("CREATE VIRTUAL TABLE files_fts5 USING fts5 (file_name, text, content = 'files');")
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
	objectsFilePath := filepath.Join(homeDir, "notebrew-objects")
	err = os.MkdirAll(objectsFilePath, 0755)
	if err != nil {
		return err
	}
	dirObjectStorage, err := nb10.NewDirObjectStorage(objectsFilePath, os.TempDir())
	if err != nil {
		return err
	}
	databaseFS, err = nb10.NewDatabaseFS(nb10.DatabaseFSConfig{
		DB:      db,
		Dialect: "sqlite",
		ErrorCode: func(err error) string {
			var sqliteErr *sqlite.Error
			if errors.As(err, &sqliteErr) {
				return strconv.Itoa(int(sqliteErr.Code()))
			}
			return ""
		},
		ObjectStorage: dirObjectStorage,
		Logger:        nbrew.Logger,
	})
	if err != nil {
		return err
	}
	// DirFS.
	filesFilePath := filepath.Join(homeDir, "notebrew-files")
	err = os.MkdirAll(filesFilePath, 0755)
	if err != nil {
		return err
	}
	directoryFS, err = nb10.NewDirectoryFS(nb10.DirectoryFSConfig{
		RootDir: filesFilePath,
	})
	if err != nil {
		return err
	}
	// ReplicatedFS.
	replicatedFS, err := nb10.NewReplicatedFS(nb10.ReplicatedFSConfig{
		Leader:                 databaseFS,
		Followers:              []nb10.FS{directoryFS},
		SynchronousReplication: false,
		Logger:                 nbrew.Logger,
	})
	if err != nil {
		return err
	}
	closers = append(closers, replicatedFS)
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
			return err
		}
	}
	_, err = fs.Stat(nbrew.FS, "site.json")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		siteConfig := nb10.SiteConfig{
			LanguageCode:   "en",
			Title:          "My Blog",
			Tagline:        "",
			Emoji:          "☕️",
			Favicon:        "",
			CodeStyle:      "onedark",
			TimezoneOffset: "+00:00",
			Description:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
			NavigationLinks: []nb10.NavigationLink{{
				Name: "Home",
				URL:  "/",
			}, {
				Name: "Posts",
				URL:  "/posts/",
			}},
		}
		b, err := json.MarshalIndent(&siteConfig, "", "  ")
		if err != nil {
			return err
		}
		writer, err := nbrew.FS.OpenWriter("site.json", 0644)
		if err != nil {
			return err
		}
		defer writer.Close()
		_, err = io.Copy(writer, bytes.NewReader(b))
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
	siteGen, err := nb10.NewSiteGenerator(context.Background(), nb10.SiteGeneratorConfig{
		FS:                 nbrew.FS,
		ContentDomain:      nbrew.ContentDomain,
		ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
		CDNDomain:          nbrew.CDNDomain,
		SitePrefix:         "",
	})
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
		creationTime := time.Now()
		err = siteGen.GeneratePage(context.Background(), "pages/index.html", string(b), creationTime, creationTime)
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
		creationTime := time.Now()
		err = siteGen.GeneratePage(context.Background(), "pages/404.html", string(b), creationTime, creationTime)
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
	// Content Security Policy.
	nbrew.ContentSecurityPolicy = "default-src 'none';" +
		" script-src 'self' 'unsafe-hashes' " + nb10.BaselineJSHash + ";" +
		" connect-src 'self';" +
		" img-src 'self' data:;" +
		" style-src 'self' 'unsafe-inline';" +
		" base-uri 'self';" +
		" form-action 'self';" +
		" manifest-src 'self';" +
		" frame-src 'self';"
	// Server.
	server = &http.Server{
		ErrorLog: log.New(&LogFilter{Stderr: os.Stderr}, "", log.LstdFlags),
		Addr:     ":6444",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme := "https://"
			if r.TLS == nil {
				scheme = "http://"
			}
			// Redirect the www subdomain to the bare domain.
			if r.Host == "www."+nbrew.CMSDomain {
				http.Redirect(w, r, scheme+nbrew.CMSDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
				return
			}
			// Redirect unclean paths to the clean path equivalent.
			if r.Method == "GET" || r.Method == "HEAD" {
				cleanPath := path.Clean(r.URL.Path)
				if cleanPath != "/" {
					_, ok := nb10.AllowedFileTypes[path.Ext(cleanPath)]
					if !ok {
						cleanPath += "/"
					}
				}
				if cleanPath != r.URL.Path {
					cleanURL := *r.URL
					cleanURL.Path = cleanPath
					http.Redirect(w, r, cleanURL.String(), http.StatusMovedPermanently)
					return
				}
			}
			nbrew.AddSecurityHeaders(w)
			r = r.WithContext(context.WithValue(r.Context(), nb10.LoggerKey, nbrew.Logger.With(
				slog.String("method", r.Method),
				slog.String("url", scheme+r.Host+r.URL.RequestURI()),
			)))
			nbrew.ServeHTTP(w, r)
		}),
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return err
		}
		// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
		const WSAEADDRINUSE = syscall.Errno(10048)
		if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
			return fmt.Errorf("notebrew is already running on http://" + nbrew.CMSDomain + "/files/")
		}
		return err
	}
	switch runtime.GOOS {
	case "linux":
		exec.Command("xdg-open", "https://localhost:6444").Start()
	case "windows":
		exec.Command("explorer.exe", "https://localhost:6444").Start()
	case "darwin":
		exec.Command("open", "https://localhost:6444").Start()
	}
	go func() {
		defer func() {
			// gui.ServerStopped <- struct{}{}
		}()
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Println(err)
		}
	}()
	go func() {
		<-gui.StopServer
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		server.Shutdown(ctx)
	}()
	// TODO: spin off a goroutine listen and serve at the end, wait for
	// incoming signals from gui.StopServer channel (unbuffered) and send out
	// signal to gui.ServerStopped channel when done (unbuffered). If a user
	// repeatedly taps the Stop notebrew button, any extra signals will simply
	// be discarded.
	return nil
}

func (gui *GUI) SyncFolder(ctx context.Context) {
	defer func() {
		gui.SyncButton.SetText("Sync folder 🔄")
		gui.SyncProgressBar.Hide()
		gui.SyncInProgress.Store(false)
		gui.SyncDone <- struct{}{}
	}()
	gui.SyncInProgress.Store(true)
	gui.SyncProgressBar.SetValue(0)
	for i := 0.0; i <= 1.0; i += 0.1 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Millisecond * 250):
		}
		gui.SyncProgressBar.SetValue(i)
	}
	// TODO: walk the files in databaseFS and fill in any missing files in dirFS.
}

func portPID(port int) (pid int, err error) {
	switch runtime.GOOS {
	case "darwin", "linux":
		cmd := exec.Command("lsof", "-n", "-P", "-i", ":"+strconv.Itoa(port))
		b, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
				// lsof also returning 1 is not necessarily an error, because it
				// also returns 1 if no result was found. Return an error only if
				// lsof also printed something to stderr.
				return -1, fmt.Errorf(string(exitErr.Stderr))
			}
		}
		var line []byte
		remainder := b
		for len(remainder) > 0 {
			line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			if !bytes.Contains(line, []byte("LISTEN")) && !bytes.Contains(line, []byte("UDP")) {
				continue
			}
			fields := strings.Fields(string(line))
			if len(fields) < 5 {
				continue
			}
			pid, err = strconv.Atoi(strings.TrimSpace(fields[1]))
			if err != nil {
				continue
			}
			return pid, nil
		}
		return -1, nil
	case "windows":
		cmd := exec.Command("netstat.exe", "-a", "-n", "-o")
		b, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
				return -1, fmt.Errorf(string(exitErr.Stderr))
			}
			return -1, err
		}
		var line []byte
		remainder := b
		for len(remainder) > 0 {
			line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			fields := strings.Fields(string(line))
			if len(fields) < 5 {
				continue
			}
			protocol := strings.TrimSpace(fields[0])
			if protocol != "TCP" && protocol != "UDP" {
				continue
			}
			if !strings.HasSuffix(strings.TrimSpace(fields[1]), ":"+strconv.Itoa(port)) {
				continue
			}
			if strings.TrimSpace(fields[3]) != "LISTENING" {
				continue
			}
			pid, err = strconv.Atoi(strings.TrimSpace(fields[4]))
			if err != nil {
				continue
			}
			return pid, nil
		}
		return -1, nil
	default:
		return -1, fmt.Errorf("unable to check if a process is listening on port %d (only macos, linux and windows are supported)", port)
	}
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
