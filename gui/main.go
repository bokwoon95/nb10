package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/bokwoon95/nb10"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Notebrew")
	myWindow.CenterOnScreen()
	var gui GUI
	gui.Mutex = &sync.Mutex{}
	gui.ContentDomainLabel = widget.NewLabel("Site URL (used in RSS feed):")
	gui.ContentDomainEntry = widget.NewEntry()
	gui.ContentDomainEntry.SetPlaceHolder("your site URL e.g. example.com")
	gui.ContentDomainEntry.SetText("example.com")
	gui.StartButton = widget.NewButton("Start notebrew ▶", func() {
		gui.StartButton.Disable()
		gui.StopButton.Enable()
		gui.OpenBrowserButton.Enable()
		// TODO: write contentdomain.txt, instantiate notebrew (blocking), run
	})
	gui.StopButton = widget.NewButton("Stop notebrew 🛑", func() {
		gui.StartButton.Enable()
		gui.StopButton.Disable()
		gui.OpenBrowserButton.Disable()
		// TODO: check if notebrew field is nil, if nil then return. if not nil then call
	})
	gui.StopButton.Disable()
	gui.OpenBrowserButton = widget.NewButton("Open browser 🌐", func() {
		// TODO: open localhost:6444
	})
	gui.OpenBrowserButton.Disable()
	gui.OpenFolderButton = widget.NewButton("Open folder 📂", func() {
		// TODO: open "$HOME/notebrew-files"
	})
	gui.SyncButton = widget.NewButton("Sync folder 🔄", func() {
		gui.Mutex.Lock()
		syncInProgress := gui.SyncInProgress
		gui.Mutex.Unlock()
		if syncInProgress {
			gui.SyncCancel()
			<-gui.SyncDone
		} else {
			ctx, cancel := context.WithCancel(context.Background())
			gui.Mutex.Lock()
			gui.SyncCancel = cancel
			gui.Mutex.Unlock()
			go gui.SyncFolder(ctx)
			gui.SyncButton.SetText("Stop sync ❌")
			gui.SyncProgressBar.Show()
		}
	})
	gui.SyncProgressBar = widget.NewProgressBar()
	gui.SyncProgressBar.Hide()
	gui.SyncDone = make(chan struct{})
	myWindow.SetContent(container.NewVBox(
		gui.ContentDomainLabel,
		gui.ContentDomainEntry,
		container.NewGridWithColumns(2, gui.StartButton, gui.StopButton),
		gui.OpenBrowserButton,
		gui.OpenFolderButton,
		gui.SyncButton,
		gui.SyncProgressBar,
	))
	myWindow.ShowAndRun()
	// TODO: instantiate a base context above, tidy up here by canceling the
	// base context after ShowAndRun() returns.
}

type GUI struct {
	Mutex              *sync.Mutex
	Notebrew           *nb10.Notebrew
	Closers            []io.Closer
	ContentDomainLabel *widget.Label
	ContentDomainEntry *widget.Entry
	StartButton        *widget.Button
	StopButton         *widget.Button
	OpenBrowserButton  *widget.Button
	OpenFolderButton   *widget.Button
	SyncButton         *widget.Button
	SyncProgressBar    *widget.ProgressBar
	SyncInProgress     bool
	SyncCancel         func()
	SyncDone           chan struct{}
}

func (gui *GUI) StartNotebrew() {
	nbrew := nb10.New()
	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	})
	nbrew.Logger = slog.New(logHandler).With(slog.String("version", nb10.Version))
}

func (gui *GUI) StopNotebrew() {
}

func (gui *GUI) SyncFolder(ctx context.Context) {
	defer func() {
		gui.SyncButton.SetText("Sync folder 🔄")
		gui.SyncProgressBar.Hide()
		gui.Mutex.Lock()
		gui.SyncInProgress = false
		gui.Mutex.Unlock()
		gui.SyncDone <- struct{}{}
	}()
	gui.Mutex.Lock()
	gui.SyncInProgress = true
	gui.Mutex.Unlock()
	gui.SyncProgressBar.SetValue(0)
	for i := 0.0; i <= 1.0; i += 0.1 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Millisecond * 250):
		}
		gui.SyncProgressBar.SetValue(i)
	}
}
