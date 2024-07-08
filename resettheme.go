package nb10

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/bokwoon95/nb10/sq"
)

func (nbrew *Notebrew) resettheme(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		ResetIndexHTML     bool   `json:"resetIndexHTML"`
		ResetAllCategories bool   `json:"resetAllCategories"`
		ResetCategory      string `json:"resetCategory"`
		ResetPostHTML      bool   `json:"resetPostHTML"`
		ResetPostListHTML  bool   `json:"resetPostListHTML"`
	}
	type Response struct {
		ContentBaseURL     string            `json:"contentBaseURL"`
		IsDatabaseFS       bool              `json:"isDatabaseFS"`
		SitePrefix         string            `json:"sitePrefix"`
		UserID             ID                `json:"userID"`
		Username           string            `json:"username"`
		DisableReason      string            `json:"disableReason"`
		Categories         []string          `json:"categories"`
		ResetIndexHTML     bool              `json:"resetIndexHTML"`
		ResetAllCategories bool              `json:"resetAllCategories"`
		ResetCategory      string            `json:"resetCategory"`
		ResetPostHTML      bool              `json:"resetPostHTML"`
		ResetPostListHTML  bool              `json:"resetPostListHTML"`
		RegenerationStats  RegenerationStats `json:"regenerationStats"`
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
			referer := nbrew.GetReferer(r)
			funcMap := map[string]any{
				"join":       path.Join,
				"base":       path.Base,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("resettheme.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/resettheme.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}

		var response Response
		_, err := nbrew.GetSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.ClearSession(w, r, "flash")
		response.ContentBaseURL = nbrew.ContentBaseURL(sitePrefix)
		response.SitePrefix = sitePrefix
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.Categories = []string{""}
		if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
			categories, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
					" AND is_dir",
				Values: []any{
					sq.StringParam("parent", path.Join(sitePrefix, "posts")),
				},
			}, func(row *sq.Row) string {
				return path.Base(row.String("file_path"))
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			response.Categories = append(response.Categories, categories...)
		} else {
			err := fs.WalkDir(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "posts"), func(filePath string, dirEntry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if dirEntry.IsDir() {
					response.Categories = append(response.Categories, path.Base(filePath))
				}
				return nil
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		writeResponse(w, r, response)
	case "POST":
		if user.DisableReason != "" {
			nbrew.AccountDisabled(w, r, user.DisableReason)
			return
		}
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			err := nbrew.SetSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "resettheme",
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, urlReplacer.Replace("/"+path.Join("files", sitePrefix, "output/themes")), http.StatusFound)
		}

		var request Request
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
				if err != nil {
					nbrew.BadRequest(w, r, err)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					nbrew.BadRequest(w, r, err)
					return
				}
			}
			request.ResetIndexHTML, _ = strconv.ParseBool(r.Form.Get("resetIndexHTML"))
			request.ResetAllCategories, _ = strconv.ParseBool(r.Form.Get("resetAllCategories"))
			request.ResetCategory = r.Form.Get("resetCategory")
			request.ResetPostHTML, _ = strconv.ParseBool(r.Form.Get("resetPostHTML"))
			request.ResetPostListHTML, _ = strconv.ParseBool(r.Form.Get("resetPostListHTML"))
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			ResetIndexHTML: request.ResetIndexHTML,
		}
		if request.ResetAllCategories {
			response.ResetAllCategories = true
			response.Categories = []string{""}
			if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
				categories, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND is_dir",
					Values: []any{
						sq.StringParam("parent", path.Join(sitePrefix, "posts")),
					},
				}, func(row *sq.Row) string {
					return path.Base(row.String("file_path"))
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.Categories = append(response.Categories, categories...)
			} else {
				err := fs.WalkDir(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "posts"), func(filePath string, dirEntry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if dirEntry.IsDir() {
						response.Categories = append(response.Categories, path.Base(filePath))
					}
					return nil
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
			}
		} else {
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
