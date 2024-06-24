package nb10

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

func (nbrew *Notebrew) importt(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		FileName string `json:"fileName"`
		Root     string `json:"root"`
	}
	type Response struct {
		ContentBaseURL string   `json:"contentBaseURL"`
		ImgDomain      string   `json:"imgDomain"`
		IsDatabaseFS   bool     `json:"isDatabaseFS"`
		SitePrefix     string   `json:"sitePrefix"`
		UserID         ID       `json:"userID"`
		Username       string   `json:"username"`
		ThemesOnly     bool     `json:"themesOnly"`
		FileName       string   `json:"fileName"`
		Root           string   `json:"root"`
		Size           int64    `json:"size"`
		FilesExist     []string `json:"filesExist"`
		FilesInvalid   []string `json:"filesInvalid"`
		FilesPasted    []string `json:"filesPasted"`
		Error          string   `json:"error"`
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
				encoder.SetIndent("", "  ")
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
				"ext":                   path.Ext,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"humanReadableFileSize": humanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
			}
			tmpl, err := template.New("import.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/import.html")
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
		response.ImgDomain = nbrew.ImgDomain
		_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
		response.UserID = user.UserID
		response.Username = user.Username
		response.SitePrefix = sitePrefix
		response.FileName = r.Form.Get("fileName")
		response.Root = path.Clean(strings.Trim(r.Form.Get("root"), "/"))
		if !strings.HasSuffix(response.FileName, ".tgz") {
			response.Error = "InvalidFileType"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "imports", response.FileName))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "FileNotExist"
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		if fileInfo.IsDir() {
			response.Error = "InvalidFileType"
			writeResponse(w, r, response)
			return
		}
		response.Size = fileInfo.Size()
		writeResponse(w, r, response)
	case "POST":
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
