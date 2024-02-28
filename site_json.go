package nb10

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (nbrew *Notebrew) siteJSON(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Request struct {
		Lang                string   `json:"lang"`
		Title               string   `json:"title"`
		Description         string   `json:"description"`
		Emoji               string   `json:"emoji"`
		Favicon             string   `json:"favicon"`
		CodeStyle           string   `json:"codeStyle"`
		NavigationLinkNames []string `json:"navigationLinkNames"`
		NavigationLinkURLs  []string `json:"navigationLinkURLs"`
	}
	type Response struct {
		Error       string     `json:"error,omitempty"`
		FormErrors  url.Values `json:"formErrors,omitempty"`
		ContentSite string     `json:"contentSite"`
		Username    NullString `json:"username"`
		SitePrefix  string     `json:"sitePrefix"`
	}

	switch r.Method {
	case "GET":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json")
				encoder := json.NewEncoder(w)
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			referer := getReferer(r)
			funcMap := map[string]any{
				"join":       path.Join,
				"base":       path.Base,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"contains":   strings.Contains,
				"stylesCSS":  func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS": func() template.JS { return template.JS(baselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("site_json.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/site_json.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
			executeTemplate(w, r, tmpl, &response)
		}
		var response Response
		_, err := nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentSite = nbrew.contentSite(sitePrefix)
		response.Username = NullString{String: username, Valid: nbrew.DB != nil}
		response.SitePrefix = sitePrefix
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		// for any field, check if it has a GET pull request data from GET parameters and use it, if not fall back to site.json.
		// TODO: if the user specifies ?numNavigationLinks as a GET parameter, use that to render the number of input fields to show the user
		// when the user clicks on an "+ add" button for navigation links, embedded in it is the correct number of numNavigationLinks that will increase the number of navigationLinks by 1. There is also a "reset" button that clears the GET paramaters and makes everything fall back to site.json.
		writeResponse(w, r, response)
	case "POST":
	default:
		methodNotAllowed(w, r)
	}
}
