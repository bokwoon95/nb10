package nb10

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

func (nbrew *Notebrew) exports(w http.ResponseWriter, r *http.Request, user User, sitePrefix, tgzFileName string) {
	type File struct {
		FileID       ID        `json:"fileID"`
		Parent       string    `json:"parent"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
	}
	type Request struct {
		Parent string
		Names  []string
	}
	type Response struct {
		ContentBaseURL  string         `json:"contentBaseURL"`
		ImgDomain       string         `json:"imgDomain"`
		IsDatabaseFS    bool           `json:"isDatabaseFS"`
		SitePrefix      string         `json:"sitePrefix"`
		UserID          ID             `json:"userID"`
		Username        string         `json:"username"`
		FileID          ID             `json:"fileID"`
		FilePath        string         `json:"filePath"`
		IsDir           bool           `json:"isDir"`
		ModTime         time.Time      `json:"modTime"`
		CreationTime    time.Time      `json:"creationTime"`
		Files           []File         `json:"files"`
		PostRedirectGet map[string]any `json:"postRedirectGet"`
	}

	switch r.Method {
	case "GET":
		if tgzFileName != "" {
			if strings.Contains(tgzFileName, "/") || !strings.HasSuffix(tgzFileName, ".tgz") {
				nbrew.notFound(w, r)
				return
			}
			file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, "exports", tgzFileName))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					nbrew.notFound(w, r)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			fileInfo, err := file.Stat()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			serveFile(w, r, file, fileInfo, fileTypes[".tgz"], "no-cache")
			return
		}
		if r.Form.Has("export") {
			var response struct {
				ContentBaseURL string `json:"contentBaseURL"`
				ImgDomain      string `json:"imgDomain"`
				IsDatabaseFS   bool   `json:"isDatabaseFS"`
				SitePrefix     string `json:"sitePrefix"`
				UserID         ID     `json:"userID"`
				Username       string `json:"username"`
				Parent         string `json:"parent"`
				Files          []File `json:"files"`
				Error          string `json:"error"`
			}
			response.ContentBaseURL = nbrew.contentBaseURL(sitePrefix)
			response.ImgDomain = nbrew.ImgDomain
			_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
			response.SitePrefix = sitePrefix
			response.UserID = user.UserID
			response.Username = user.Username
			referer := nbrew.getReferer(r)
			funcMap := map[string]any{
				"join":                  path.Join,
				"ext":                   path.Ext,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"humanReadableFileSize": humanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
			}
			tmpl, err := template.New("export.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/export.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.executeTemplate(w, r, tmpl, &response)
			return
		}
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
			referer := nbrew.getReferer(r)
			clipboard := make(url.Values)
			isInClipboard := make(map[string]bool)
			cookie, _ := r.Cookie("clipboard")
			if cookie != nil {
				values, err := url.ParseQuery(cookie.Value)
				if err == nil && values.Get("sitePrefix") == sitePrefix {
					if values.Has("cut") {
						clipboard.Set("cut", "")
					}
					clipboard.Set("sitePrefix", values.Get("sitePrefix"))
					clipboard.Set("parent", values.Get("parent"))
					for _, name := range values["name"] {
						if isInClipboard[name] {
							continue
						}
						clipboard.Add("name", name)
						isInClipboard[name] = true
					}
				}
			}
			funcMap := map[string]any{
				"join":                  path.Join,
				"dir":                   path.Dir,
				"base":                  path.Base,
				"ext":                   path.Ext,
				"hasPrefix":             strings.HasPrefix,
				"hasSuffix":             strings.HasSuffix,
				"trimPrefix":            strings.TrimPrefix,
				"trimSuffix":            strings.TrimSuffix,
				"humanReadableFileSize": humanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
				"clipboard":             func() url.Values { return clipboard },
				"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
				"float64ToInt64":        func(n float64) int64 { return int64(n) },
				"head": func(s string) string {
					head, _, _ := strings.Cut(s, "/")
					return head
				},
				"tail": func(s string) string {
					_, tail, _ := strings.Cut(s, "/")
					return tail
				},
				"generateBreadcrumbLinks": func(sitePrefix, filePath string) template.HTML {
					var b strings.Builder
					b.WriteString("<a href='/files/'>files</a>")
					segments := strings.Split(filePath, "/")
					if sitePrefix != "" {
						segments = append([]string{sitePrefix}, segments...)
					}
					for i := 0; i < len(segments); i++ {
						if segments[i] == "" {
							continue
						}
						href := "/files/" + path.Join(segments[:i+1]...) + "/"
						b.WriteString(" / <a href='" + href + "'>" + segments[i] + "</a>")
					}
					b.WriteString(" /")
					return template.HTML(b.String())
				},
				"isInClipboard": func(name string) bool {
					if sitePrefix != clipboard.Get("sitePrefix") {
						return false
					}
					if clipboard.Get("parent") != "exports" {
						return false
					}
					return isInClipboard[name]
				},
			}
			if r.Form.Has("export") {
				tmpl, err := template.New("export.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/export.html")
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
				nbrew.executeTemplate(w, r, tmpl, &response)
			}
			tmpl, err := template.New("exports.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/exports.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.executeTemplate(w, r, tmpl, &response)
		}

		fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "exports"))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		var response Response
		_, err = nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentBaseURL = nbrew.contentBaseURL(sitePrefix)
		response.ImgDomain = nbrew.ImgDomain
		_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
		response.SitePrefix = sitePrefix
		response.UserID = user.UserID
		response.Username = user.Username
		if fileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
			response.FileID = fileInfo.FileID
			response.ModTime = fileInfo.ModTime()
			response.CreationTime = fileInfo.CreationTime
		} else {
			var absolutePath string
			if dirFS, ok := nbrew.FS.(*DirFS); ok {
				absolutePath = path.Join(dirFS.RootDir, response.SitePrefix, response.FilePath)
			}
			response.CreationTime = CreationTime(absolutePath, fileInfo)
		}
		response.FilePath = "exports"
		response.IsDir = true
		writeResponse(w, r, response)
	case "POST":
		if tgzFileName != "" {
			nbrew.notFound(w, r)
			return
		}
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
