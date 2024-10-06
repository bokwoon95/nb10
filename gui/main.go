package main

import (
	"context"
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
	myWindow.CenterOnScreen() // Center the window on the screen
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
	})
	gui.StopButton = widget.NewButton("Stop notebrew 🛑", func() {
		gui.StartButton.Enable()
		gui.StopButton.Disable()
		gui.OpenBrowserButton.Disable()
	})
	gui.StopButton.Disable()
	gui.OpenBrowserButton = widget.NewButton("Open browser 🌐", func() {})
	gui.OpenBrowserButton.Disable()
	gui.OpenFolderButton = widget.NewButton("Open folder 📂", func() {})
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
}

type GUI struct {
	Mutex              *sync.Mutex
	Notebrew           *nb10.Notebrew
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

func main1() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Notebrew")
	// myWindow.Resize(fyne.NewSize(300, 300)) // Set initial window size to 900x600 (3:2 aspect ratio)
	myWindow.CenterOnScreen() // Center the window on the screen
	contentDomainEntry := widget.NewEntry()
	contentDomainEntry.SetPlaceHolder("your site URL e.g. example.com")
	// contentDomainEntry.SetText("example.com")
	progress := widget.NewProgressBar()
	progress.Hide()
	var s1, s2, open *widget.Button
	s1 = widget.NewButton("Start notebrew ▶", func() {
		s1.Disable()
		s2.Enable()
		open.Enable()
	})
	s2 = widget.NewButton("Stop notebrew 🛑", func() {
		s2.Disable()
		s1.Enable()
		open.Disable()
	})
	s2.Disable()
	open = widget.NewButton("Open browser 🌐", func() {})
	open.Disable()
	var syncFolder *widget.Button
	syncFolder = widget.NewButton("Sync folder 🔄", func() {
		go func() {
			syncFolder.SetText("Stop sync ❌")
			progress.Show()
			for i := 0.0; i <= 1.0; i += 0.1 {
				time.Sleep(time.Millisecond * 250)
				progress.SetValue(i)
			}
			progress.Hide()
			syncFolder.SetText("Sync folder 🔄")
		}()
	})
	myWindow.SetContent(container.NewVBox(
		widget.NewLabel("Site URL (used in RSS feed):"),
		contentDomainEntry,
		container.NewGridWithColumns(2, s1, s2),
		open,
		widget.NewButton("Open folder 📂", func() {}),
		syncFolder,
		progress,
	))
	myWindow.ShowAndRun()
}
