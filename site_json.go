package nb10

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
)

var chromaStyles = map[string]bool{
	"abap": true, "algol": true, "algol_nu": true, "api": true, "arduino": true,
	"autumn": true, "average": true, "base16-snazzy": true, "borland": true, "bw": true,
	"catppuccin-frappe": true, "catppuccin-latte": true, "catppuccin-macchiato": true,
	"catppuccin-mocha": true, "colorful": true, "compat": true, "doom-one": true,
	"doom-one2": true, "dracula": true, "emacs": true, "friendly": true, "fruity": true,
	"github-dark": true, "github": true, "gruvbox-light": true, "gruvbox": true,
	"hr_high_contrast": true, "hrdark": true, "igor": true, "lovelace": true, "manni": true,
	"modus-operandi": true, "modus-vivendi": true, "monokai": true, "monokailight": true,
	"murphy": true, "native": true, "nord": true, "onedark": true, "onesenterprise": true,
	"paraiso-dark": true, "paraiso-light": true, "pastie": true, "perldoc": true,
	"pygments": true, "rainbow_dash": true, "rose-pine-dawn": true, "rose-pine-moon": true,
	"rose-pine": true, "rrt": true, "solarized-dark": true, "solarized-dark256": true,
	"solarized-light": true, "swapoff": true, "tango": true, "trac": true, "vim": true,
	"vs": true, "vulcan": true, "witchhazel": true, "xcode-dark": true, "xcode": true,
}

func (nbrew *Notebrew) siteJSON(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type Request struct {
		Title               string   `json:"title"`
		Emoji               string   `json:"emoji"`
		Favicon             string   `json:"favicon"`
		CodeStyle           string   `json:"codeStyle"`
		Description         string   `json:"description"`
		NavigationLinkNames []string `json:"navigationLinkNames"`
		NavigationLinkURLs  []string `json:"navigationLinkURLs"`
	}
	type Response struct {
		Error               string     `json:"error,omitempty"`
		FormErrors          url.Values `json:"formErrors,omitempty"`
		ContentSite         string     `json:"contentSite"`
		Username            NullString `json:"username"`
		SitePrefix          string     `json:"sitePrefix"`
		Title               string     `json:"title"`
		Emoji               string     `json:"emoji"`
		Favicon             string     `json:"favicon"`
		CodeStyle           string     `json:"codeStyle"`
		Description         string     `json:"description"`
		NavigationLinkNames []string   `json:"navigationLinkNames"`
		NavigationLinkURLs  []string   `json:"navigationLinkURLs"`
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
				"join":         path.Join,
				"base":         path.Base,
				"hasPrefix":    strings.HasPrefix,
				"trimPrefix":   strings.TrimPrefix,
				"contains":     strings.Contains,
				"stylesCSS":    func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS":   func() template.JS { return template.JS(baselineJS) },
				"referer":      func() string { return referer },
				"chromaStyles": func() map[string]bool { return chromaStyles },
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
