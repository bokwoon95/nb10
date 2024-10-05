package main

import (
	"time"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Notebrew")
	// myWindow.Resize(fyne.NewSize(300, 300)) // Set initial window size to 900x600 (3:2 aspect ratio)
	myWindow.CenterOnScreen() // Center the window on the screen
	contentDomainEntry := widget.NewEntry()
	contentDomainEntry.SetPlaceHolder("your site URL e.g. example.com")
	contentDomainEntry.SetText("example.com")
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
		widget.NewLabel("Site URL"),
		contentDomainEntry,
		container.NewGridWithColumns(2, s1, s2),
		open,
		widget.NewButton("Open folder 📂", func() {}),
		syncFolder,
		progress,
	))
	myWindow.ShowAndRun()
}
