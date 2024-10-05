package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

var server *http.Server
var wg sync.WaitGroup

func main() {
	// Create a new application
	myApp := app.New()
	myWindow := myApp.NewWindow("HTTP Server UI")
	myWindow.Resize(fyne.NewSize(300, 300)) // Set initial window size to 900x600 (3:2 aspect ratio)
	myWindow.CenterOnScreen() // Center the window on the screen

	contentDomainEntry := widget.NewEntry()
	contentDomainEntry.SetPlaceHolder("Enter content domain")

	// Start server button
	var startServerButton *widget.Button
	startServerButton = widget.NewButton("Start server", func() {
		contentDomain := contentDomainEntry.Text

		startServer(contentDomain)

		// Change UI to show server started status
		listeningLabel := widget.NewLabel(fmt.Sprintf("Listening on port 6444..."))

		openBrowserButton := widget.NewButton("Open browser", func() {
			openBrowser(fmt.Sprintf("http://localhost:6444"))
		})

		stopServerButton := widget.NewButton("Stop server", func() {
			stopServer(myWindow, contentDomainEntry, startServerButton)
		})

		buttonContainer := container.NewVBox(listeningLabel, openBrowserButton, stopServerButton)
		myWindow.SetContent(buttonContainer)
	})

	// Form container
	form := container.NewVBox(
		widget.NewLabel("Content Domain"),
		contentDomainEntry,
		widget.NewLabel("Files Provider"),
		startServerButton,
	)

	myWindow.SetContent(form)
	myWindow.ShowAndRun()
}

// Start HTTP server
func startServer(contentDomain string) {
	address := fmt.Sprintf("localhost:%d", 6444)

	server = &http.Server{Addr: address, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(fmt.Sprintf("Hello from server running on port %d!\n", 6444)))
		w.Write([]byte(fmt.Sprintf("Content Domain: %s\n", contentDomain)))
	})}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not listen on %s: %v\n", address, err)
		}
	}()
	log.Printf("Server started on port 6444...\n")
}

// Stop the server
func stopServer(myWindow fyne.Window, contentDomainEntry *widget.Entry, startServerButton *widget.Button) {
	if server != nil {
		if err := server.Close(); err != nil {
			log.Printf("Error stopping server: %v\n", err)
		}
		wg.Wait()
		log.Println("Server stopped")
		server = nil
	}

	contentDomainEntry.SetText("")

	form := container.NewVBox(
		widget.NewLabel("Port (number)"),
		widget.NewLabel("Content Domain"),
		contentDomainEntry,
		widget.NewLabel("Files Provider"),
		startServerButton,
	)

	myWindow.SetContent(form)
}

// Open a browser window with the given URL
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("explorer.exe", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Printf("Failed to open browser: %v", err)
	}
}
