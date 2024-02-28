package nb10

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strconv"
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
				"incr":         func(n int) int { return n + 1 },
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
		b, err := fs.ReadFile(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "site.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		var config struct {
			Lang            string
			Title           string
			Emoji           string
			Favicon         string
			CodeStyle       string
			Description     string
			NavigationLinks []NavigationLink
		}
		if len(b) > 0 {
			err := json.Unmarshal(b, &config)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		response.Title = strings.TrimSpace(r.Form.Get("title"))
		if response.Title == "" {
			response.Title = config.Title
		}
		if response.Title == "" {
			response.Title = "My Blog"
		}
		response.Emoji = strings.TrimSpace(r.Form.Get("emoji"))
		if response.Emoji == "" {
			response.Emoji = config.Emoji
		}
		response.Favicon = strings.TrimSpace(r.Form.Get("favicon"))
		if response.Favicon == "" {
			response.Favicon = config.Favicon
		}
		response.CodeStyle = strings.TrimSpace(r.Form.Get("codeStyle"))
		if response.CodeStyle == "" {
			response.CodeStyle = config.CodeStyle
		}
		if !chromaStyles[response.CodeStyle] {
			response.CodeStyle = "onedark"
		}
		response.Description = strings.TrimSpace(r.Form.Get("description"))
		if response.Description == "" {
			response.Description = config.Description
		}
		if response.Description == "" {
			response.Description = "# Hello World!\n\nWelcome to my blog."
		}
		navigationLinkNames := r.Form["navigationLinkName"]
		navigationLinkURLs := r.Form["naviationLinkURL"]
		if len(navigationLinkNames) > 0 && len(navigationLinkNames) == len(navigationLinkURLs) {
			response.NavigationLinkNames = navigationLinkNames
			response.NavigationLinkURLs = navigationLinkURLs
		} else {
			for _, navigationLink := range config.NavigationLinks {
				response.NavigationLinkNames = append(response.NavigationLinkNames, navigationLink.Name)
				response.NavigationLinkURLs = append(response.NavigationLinkURLs, string(navigationLink.URL))
			}
		}
		numNavigationLinks, err := strconv.Atoi(r.Form.Get("numNavigationLinks"))
		if err == nil && numNavigationLinks > len(response.NavigationLinkNames) {
			for i := len(response.NavigationLinkNames); i <= numNavigationLinks; i++ {
				response.NavigationLinkNames = append(response.NavigationLinkNames, "")
				response.NavigationLinkURLs = append(response.NavigationLinkURLs, "")
			}
		}
		writeResponse(w, r, response)
	case "POST":
	default:
		methodNotAllowed(w, r)
	}
}
