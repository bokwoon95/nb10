package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/bokwoon95/nb10"
)

func (nbrew *Notebrewx) signup(w http.ResponseWriter, r *http.Request) {
	type Request struct {
		Email string
	}
	type Response struct {
		Email      string     `json:"email"`
		Error      string     `json:"error"`
		FormErrors url.Values `json:"formErrors"`
	}

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if r.Method == "HEAD" {
					w.WriteHeader(http.StatusOK)
					return
				}
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			funcMap := map[string]any{
				"join":       path.Join,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"contains":   strings.Contains,
				"stylesCSS":  func() template.CSS { return template.CSS(nb10.StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(nb10.BaselineJS) },
				"referer":    func() string { return r.Referer() },
			}
			tmpl, err := template.New("signup.html").Funcs(funcMap).ParseFS(runtimeFS, "embed/signup.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}
		var response Response
		_, err := nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		writeResponse(w, r, response)
	case "POST":
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
