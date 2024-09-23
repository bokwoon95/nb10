package main

import (
	"log"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

func main() {
	// Initialize the Gio window
	go func() {
		var w app.Window
		w.Option(app.Title("Gio Example"))

		// Create a new theme using default fonts
		th := material.NewTheme()
		th.Shaper = text.NewShaper(text.WithCollection(gofont.Collection()))

		// Declare the widgets
		var (
			portInput          widget.Editor
			contentDomainInput widget.Editor
			filesProviderRadio widget.Enum
		)

		// Set editors to be single-line
		portInput.SingleLine = true
		contentDomainInput.SingleLine = true

		// Default radio button value
		filesProviderRadio.Value = "directory"

		// Event loop
		var ops op.Ops
		for {
			switch e := w.Event().(type) {
			case app.DestroyEvent:
				// Exit the application when the window is closed
				log.Fatal(e.Err)
				return
			case app.FrameEvent:
				// Obtain the layout context from the FrameEvent
				gtx := layout.Context{
					Ops:    &ops,
					Now:    e.Now,
					Metric: e.Metric,
					Constraints: layout.Constraints{
						Max: e.Size,
					},
				}
				layout.Flex{
					Axis: layout.Vertical,
				}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.Label(th, unit.Sp(14), "Port (number)").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.Editor(th, &portInput, "Enter Port").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.Label(th, unit.Sp(14), "Content Domain").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.Editor(th, &contentDomainInput, "Enter Content Domain").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.Label(th, unit.Sp(14), "Files Provider").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.RadioButton(th, &filesProviderRadio, "directory", "Directory").Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.RadioButton(th, &filesProviderRadio, "database", "Database").Layout(gtx)
					}),
				)
				// Commit the frame
				e.Frame(gtx.Ops)
			}
		}
	}()

	// Start the Gio app
	app.Main()
}
