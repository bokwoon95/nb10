package main

import (
	"bytes"
	"context"
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
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/bokwoon95/nb10"
)

func main() {
	var gui GUI
	gui.App = app.New()
	gui.Window = gui.App.NewWindow("Notebrew")
	gui.Window.Resize(fyne.NewSize(600, 450))
	gui.Window.CenterOnScreen()
	gui.StartServer = make(chan struct{})
	gui.StopServer = make(chan struct{})
	err := func() error {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		// contentdomain.txt
		configDir := filepath.Join(homeDir, "notebrew-config")
		b, err := os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		contentDomain := string(bytes.TrimSpace(b))
		if contentDomain == "" {
			contentDomain = "example.com"
		}
		// port.txt
		b, err = os.ReadFile(filepath.Join(configDir, "port.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
		}
		port := string(bytes.TrimSpace(b))
		_, err = strconv.Atoi(port)
		if err != nil {
			port = "6444"
		}
		// files.json
		b, err = os.ReadFile(filepath.Join(configDir, "files.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
		}
		b = bytes.TrimSpace(b)
		var filesConfig struct {
			Provider string `json:"provider"`
			FilePath string `json:"filePath"`
		}
		if len(b) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(b))
			err = decoder.Decode(&filesConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
			}
		}
		if filesConfig.FilePath == "" {
			filesConfig.FilePath = filepath.Join(homeDir, "notebrew-files")
		}
		// Logger.
		logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			AddSource: true,
		})
		gui.Logger = slog.New(logHandler).With(slog.String("version", nb10.Version))
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
		gui.ContentDomainLabel = widget.NewLabel("Blog URL:")
		gui.ContentDomainEntry = widget.NewEntry()
		gui.ContentDomainEntry.SetPlaceHolder("your site URL e.g. example.com")
		gui.ContentDomainEntry.SetText(contentDomain)
		gui.PortLabel = widget.NewLabel("Port:")
		gui.PortEntry = widget.NewEntry()
		gui.PortEntry.SetPlaceHolder("port that Notebrew listens on e.g. 6444")
		gui.PortEntry.SetText(port)
		gui.FolderValueLabel = widget.NewLabel(filesConfig.FilePath)
		gui.FolderLabel = widget.NewLabel("Directory:")
		gui.FolderValueLabel = widget.NewLabel(filesConfig.FilePath)
		gui.FolderButton = widget.NewButton("📂", func() {
			// Open folder dialog
			folderDialog := dialog.NewFolderOpen(
				func(uri fyne.ListableURI, err error) {
					if err != nil {
						dialog.ShowError(err, gui.Window)
						return
					}
					if uri == nil {
						// No folder selected, so just return
						return
					}
					// Display the selected folder path
					gui.FolderValueLabel.SetText(uri.Path())
				}, gui.Window)
			// Show the folder dialog
			folderDialog.Show()
		})
		gui.StartButton = widget.NewButton("Start Notebrew ▶", func() {
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
			go func() {
				filesConfig.Provider = "directory"
				// TODO: persist port.txt
			}()
			go func() {
				// TODO: persist files.json
			}()
			select {
			case gui.StartServer <- struct{}{}:
			default:
			}
		})
		gui.StopButton = widget.NewButton("Stop Notebrew 🛑", func() {
			select {
			case gui.StopServer <- struct{}{}:
			default:
			}
		})
		gui.StopButton.Disable()
		gui.OpenBrowserButton = widget.NewButton("Open Browser 🌐", func() {
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
		gui.Window.SetContent(container.NewVBox(
			container.New(layout.NewFormLayout(),
				gui.ContentDomainLabel, gui.ContentDomainEntry,
				gui.PortLabel, gui.PortEntry,
				gui.FolderLabel, container.NewHBox(gui.FolderValueLabel, layout.NewSpacer(), gui.FolderButton),
			),
			container.NewGridWithColumns(2, gui.StartButton, gui.StopButton),
			gui.OpenBrowserButton,
		))
		go gui.ServerLoop()
		gui.Window.ShowAndRun()
		return nil
	}()
	if err != nil {
		gui.Window.SetTitle("Error starting notebrew")
		gui.Window.SetContent(widget.NewLabel(err.Error()))
		gui.Window.ShowAndRun()
		os.Exit(1)
	}
}

type GUI struct {
	App                fyne.App
	Window             fyne.Window
	Logger             *slog.Logger
	DirectoryFS        *nb10.DirectoryFS // TODO: remove.
	StartServer        chan struct{}
	StopServer         chan struct{}
	ContentDomainLabel *widget.Label
	ContentDomainEntry *widget.Entry
	PortLabel          *widget.Label
	PortEntry          *widget.Entry
	FolderLabel        *widget.Label
	FolderValueLabel   *widget.Label
	FolderButton       *widget.Button
	StartButton        *widget.Button
	StopButton         *widget.Button
	OpenBrowserButton  *widget.Button
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

func (gui *GUI) StartServer2(homeDir string, contentDomain string) error {
	var nbrew *nb10.Notebrew
	var server *http.Server
	nbrew = nb10.New()
	nbrew.Logger = gui.Logger
	nbrew.CMSDomain = "localhost:6444"
	nbrew.ContentDomain = contentDomain
	nbrew.ContentDomainHTTPS = true
	nbrew.Port = 6444
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
		err := nbrew.FS.Mkdir(dir, 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	_, err := fs.Stat(nbrew.FS, "site.json")
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
