package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func main() {
	// Create a new Fyne application
	myApp := app.New()
	myWindow := myApp.NewWindow("Folder Picker Example")

	// Label to display selected folder path
	selectedFolderLabel := widget.NewLabel("No folder selected")

	// Create a button to trigger the folder picker dialog
	folderPickerButton := widget.NewButton("Select Folder", func() {
		// Open folder dialog
		folderDialog := dialog.NewFolderOpen(
			func(uri fyne.ListableURI, err error) {
				if err != nil {
					dialog.ShowError(err, myWindow)
					return
				}
				if uri == nil {
					// No folder selected, so just return
					return
				}

				// Display the selected folder path
				selectedFolderLabel.SetText(fmt.Sprintf("Selected folder: %s", uri.Path()))
			}, myWindow)

		// Show the folder dialog
		folderDialog.Show()
	})

	// Create a layout to contain the button and label
	content := container.NewVBox(folderPickerButton, selectedFolderLabel)

	// Set the content of the window and display it
	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(600, 500))
	myWindow.ShowAndRun()
}
