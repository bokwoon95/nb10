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
	stop := widget.NewButton("stop sync ❌", func() {})
	stop.Hide()
	myWindow.SetContent(container.NewVBox(
		widget.NewLabel("Site URL"),
		contentDomainEntry,
		container.NewGridWithColumns(2, widget.NewButton("Start notebrew ▶", func() {}), widget.NewButton("Stop notebrew 🛑", func() {})),
		widget.NewButton("Open browser 🌐", func() {}),
		widget.NewButton("Open output folder 📂", func() {}),
		widget.NewButton("Sync output folder 🔄", func() {
			go func() {
				progress.Show()
				stop.Show()
				for i := 0.0; i <= 1.0; i += 0.1 {
					time.Sleep(time.Millisecond * 250)
					progress.SetValue(i)
				}
				progress.Hide()
				stop.Hide()
			}()
		}),
		progress,
		stop,
	))
	myWindow.ShowAndRun()
}
