package nb10

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/bokwoon95/nb10/sq"
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

func (nbrew *Notebrew) siteJSON(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type NavigationLink struct {
		Name string       `json:"name"`
		URL  template.URL `json:"url"`
	}
	type Request struct {
		Title           string           `json:"title"`
		Emoji           string           `json:"emoji"`
		Favicon         string           `json:"favicon"`
		CodeStyle       string           `json:"codeStyle"`
		Description     string           `json:"description"`
		NavigationLinks []NavigationLink `json:"navigationLinks"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		Title             string            `json:"title"`
		Emoji             string            `json:"emoji"`
		Favicon           string            `json:"favicon"`
		CodeStyle         string            `json:"codeStyle"`
		Description       string            `json:"description"`
		NavigationLinks   []NavigationLink  `json:"navigationLinks"`
		StorageUsed       int64             `json:"storageUsed"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}
	normalizeRequest := func(request Request) Request {
		if request.Title == "" {
			request.Title = "My Blog"
		}
		if request.Emoji == "" {
			request.Emoji = "☕"
		}
		if !chromaStyles[request.CodeStyle] {
			request.CodeStyle = "onedark"
		}
		if request.Description == "" {
			request.Description = "# Hello World!\n\nWelcome to my blog."
		}
		var home string
		siteName := strings.TrimPrefix(sitePrefix, "@")
		if siteName == "" {
			home = "home"
		} else if strings.Contains(siteName, ".") {
			home = siteName
		} else {
			home = siteName + "." + nbrew.ContentDomain
		}
		if len(request.NavigationLinks) == 0 {
			request.NavigationLinks = []NavigationLink{
				{Name: home, URL: "/"},
				{Name: "posts", URL: "/posts/"},
			}
		}
		return request
	}

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "HEAD" {
					w.WriteHeader(http.StatusOK)
					return
				}
				encoder := json.NewEncoder(w)
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			referer := nbrew.getReferer(r)
			funcMap := map[string]any{
				"join":                  path.Join,
				"base":                  path.Base,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"contains":              strings.Contains,
				"humanReadableFileSize": humanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
				"chromaStyles":          func() map[string]bool { return chromaStyles },
				"incr":                  func(n int) int { return n + 1 },
			}
			tmpl, err := template.New("site_json.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/site_json.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.executeTemplate(w, r, tmpl, &response)
		}
		var response Response
		_, err := nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentBaseURL = nbrew.contentBaseURL(sitePrefix)
		_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
		response.UserID = user.UserID
		response.Username = user.Username
		response.SitePrefix = sitePrefix
		b, err := fs.ReadFile(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "site.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		var request Request
		if len(b) > 0 {
			err := json.Unmarshal(b, &request)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		}
		request = normalizeRequest(request)
		response.Title = request.Title
		response.Emoji = request.Emoji
		response.Favicon = request.Favicon
		response.CodeStyle = request.CodeStyle
		response.Description = request.Description
		response.NavigationLinks = request.NavigationLinks
		if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
			// notes pages posts output
			if sitePrefix == "" {
				response.StorageUsed, err = sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE file_path LIKE 'notes/%' OR file_path LIKE 'pages/%' OR file_path LIKE 'posts/%' OR file_path LIKE 'output/%'",
				}, func(row *sq.Row) int64 {
					return row.Int64("sum(coalesce(size, 0))")
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			} else {
				response.StorageUsed, err = sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE file_path LIKE {pattern} ESCAPE '\\'",
					Values: []any{
						sq.StringParam("pattern", wildcardReplacer.Replace(sitePrefix)+"/%"),
					},
				}, func(row *sq.Row) int64 {
					return row.Int64("sum(coalesce(size, 0))")
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			}
		}
		writeResponse(w, r, response)
	case "POST":
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
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "site.json",
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "site.json"), http.StatusFound)
		}

		var request Request
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				nbrew.badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
				if err != nil {
					nbrew.badRequest(w, r, err)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					nbrew.badRequest(w, r, err)
					return
				}
			}
			request.Title = r.Form.Get("title")
			request.Emoji = r.Form.Get("emoji")
			request.Favicon = r.Form.Get("favicon")
			request.CodeStyle = r.Form.Get("codeStyle")
			request.Description = r.Form.Get("description")
			navigationLinkNames := r.Form["navigationLinkName"]
			navigationLinkURLs := r.Form["navigationLinkURL"]
			for i := range navigationLinkNames {
				if i >= len(navigationLinkURLs) {
					break
				}
				request.NavigationLinks = append(request.NavigationLinks, NavigationLink{
					Name: navigationLinkNames[i],
					URL:  template.URL(navigationLinkURLs[i]),
				})
			}
		default:
			nbrew.unsupportedContentType(w, r)
			return
		}

		request = normalizeRequest(request)
		b, err := json.MarshalIndent(&request, "", "  ")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, "site.json"), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.Copy(writer, bytes.NewReader(b))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		err = writer.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		regenerationStats, err := nbrew.RegenerateSite(r.Context(), sitePrefix)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		response := Response{
			ContentBaseURL:    nbrew.contentBaseURL(sitePrefix),
			UserID:            user.UserID,
			Username:          user.Username,
			SitePrefix:        sitePrefix,
			Title:             request.Title,
			Emoji:             request.Emoji,
			Favicon:           request.Favicon,
			CodeStyle:         request.CodeStyle,
			Description:       request.Description,
			NavigationLinks:   request.NavigationLinks,
			RegenerationStats: regenerationStats,
		}
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
