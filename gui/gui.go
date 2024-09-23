package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"

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

	// Input widgets
	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("Enter port number")

	contentDomainEntry := widget.NewEntry()
	contentDomainEntry.SetPlaceHolder("Enter content domain")

	// Radio group for files provider
	filesProviderRadio := widget.NewRadioGroup([]string{"Directory", "Database"}, func(selected string) {
		log.Printf("Selected files provider: %s", selected)
	})

	// Start server button
	var startServerButton *widget.Button
	startServerButton = widget.NewButton("Start server", func() {
		port, err := strconv.Atoi(portEntry.Text)
		if err != nil || port <= 0 {
			log.Println("Invalid port number")
			return
		}
		contentDomain := contentDomainEntry.Text

		filesProvider := filesProviderRadio.Selected
		if filesProvider == "" {
			log.Println("No files provider selected")
			return
		}

		startServer(port, contentDomain, filesProvider)

		// Change UI to show server started status
		listeningLabel := widget.NewLabel(fmt.Sprintf("Listening on port %d...", port))

		openBrowserButton := widget.NewButton("Open browser", func() {
			openBrowser(fmt.Sprintf("http://localhost:%d", port))
		})

		stopServerButton := widget.NewButton("Stop server", func() {
			stopServer(myWindow, portEntry, contentDomainEntry, filesProviderRadio, startServerButton)
		})

		buttonContainer := container.NewVBox(listeningLabel, openBrowserButton, stopServerButton)
		myWindow.SetContent(buttonContainer)
	})

	// Form container
	form := container.NewVBox(
		widget.NewLabel("Port (number)"),
		portEntry,
		widget.NewLabel("Content Domain"),
		contentDomainEntry,
		widget.NewLabel("Files Provider"),
		filesProviderRadio,
		startServerButton,
	)

	myWindow.SetContent(form)
	myWindow.ShowAndRun()
}

// Start HTTP server
func startServer(port int, contentDomain string, filesProvider string) {
	address := fmt.Sprintf(":%d", port)

	server = &http.Server{Addr: address, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(fmt.Sprintf("Hello from server running on port %d!\n", port)))
		w.Write([]byte(fmt.Sprintf("Content Domain: %s\n", contentDomain)))
		w.Write([]byte(fmt.Sprintf("Files Provider: %s\n", filesProvider)))
	})}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not listen on %s: %v\n", address, err)
		}
	}()
	log.Printf("Server started on port %d...\n", port)
}

// Stop the server
func stopServer(myWindow fyne.Window, portEntry, contentDomainEntry *widget.Entry, filesProviderRadio *widget.RadioGroup, startServerButton *widget.Button) {
	if server != nil {
		if err := server.Close(); err != nil {
			log.Printf("Error stopping server: %v\n", err)
		}
		wg.Wait()
		log.Println("Server stopped")
		server = nil
	}

	// Reset the UI to initial form state
