package main

import (
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Fyne Example")

	// Create input fields
	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("Port (number)")

	contentDomainEntry := widget.NewEntry()
	contentDomainEntry.SetPlaceHolder("Content Domain")

	// Create radio buttons for the "Files Provider" options
	filesProviderRadio := widget.NewRadioGroup([]string{"Directory", "Database"}, func(selected string) {
		// This function will be triggered when a selection is made
	})
	filesProviderRadio.SetSelected("Directory") // Set default selection

	// Arrange the components in a vertical box
	content := container.NewVBox(
		widget.NewLabel("Port (number)"),
		portEntry,
		widget.NewLabel("Content Domain"),
		contentDomainEntry,
		widget.NewLabel("Files Provider"),
		filesProviderRadio,
	)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}
