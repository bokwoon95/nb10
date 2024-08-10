package nb10

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) image(w http.ResponseWriter, r *http.Request, user User, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		SitePrefix        string            `json:"sitePrefix"`
		CDNDomain         string            `json:"cdnDomain"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		FileID            ID                `json:"fileID"`
		FilePath          string            `json:"filePath"`
		IsDir             bool              `json:"isDir"`
		Size              int64             `json:"size"`
		ModTime           time.Time         `json:"modTime"`
		CreationTime      time.Time         `json:"creationTime"`
		Content           string            `json:"content"`
		AltText           string            `json:"altText"`
		URL               template.URL      `json:"url"`
		BelongsTo         string            `json:"belongsTo"`
		PreviousImageID   ID                `json:"previousImageID"`
		PreviousImageName string            `json:"previousImageName"`
		NextImageID       ID                `json:"nextImageID"`
		NextImageName     string            `json:"nextImageName"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}

	switch r.Method {
	case "GET", "HEAD":
		if r.Form.Has("raw") {
			file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(".", sitePrefix, filePath))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					nbrew.NotFound(w, r)
					return
				}
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			defer file.Close()
			fileType, ok := AllowedFileTypes[path.Ext(filePath)]
			if !ok {
				nbrew.NotFound(w, r)
				return
			}
			ServeFile(w, r, path.Base(filePath), fileInfo.Size(), fileType, file, "max-age=2592000, stale-while-revalidate=31536000" /* 1 month, 1 year */)
			return
		}
		var response Response
		_, err := nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		response.ContentBaseURL = nbrew.ContentBaseURL(sitePrefix)
		response.SitePrefix = sitePrefix
		response.CDNDomain = nbrew.CDNDomain
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		if databaseFileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
			response.FileID = databaseFileInfo.FileID
			response.ModTime = databaseFileInfo.ModTime()
			response.CreationTime = databaseFileInfo.CreationTime
		} else {
			var absolutePath string
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				var directoryFS *DirectoryFS
				if v.As(&directoryFS) {
					absolutePath = path.Join(directoryFS.RootDir, sitePrefix, filePath)
				}
			}
			response.CreationTime = CreationTime(absolutePath, fileInfo)
		}
		response.FilePath = filePath
		response.Size = fileInfo.Size()
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		databaseFS, ok := &DatabaseFS{}, false
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			ok = v.As(&databaseFS)
		}
		if ok {
			response.IsDatabaseFS = true
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				extFilter := sq.Expr("1 = 1")
				if len(imgExts) > 0 {
					var b strings.Builder
					args := make([]any, 0, len(imgExts))
					b.WriteString("(")
					for i, ext := range imgExts {
						if i > 0 {
							b.WriteString(" OR ")
						}
						b.WriteString("file_path LIKE {} ESCAPE '\\'")
						args = append(args, "%"+wildcardReplacer.Replace(ext))
					}
					b.WriteString(")")
					extFilter = sq.Expr(b.String(), args...)
				}
				result, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND file_path < {filePath}" +
						" AND {extFilter}" +
						" ORDER BY file_path DESC" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(response.SitePrefix, path.Dir(response.FilePath))),
						sq.StringParam("filePath", path.Join(response.SitePrefix, response.FilePath)),
						sq.Param("extFilter", extFilter),
					},
				}, func(row *sq.Row) (result struct {
					FileID   ID
					FilePath string
				}) {
					result.FileID = row.UUID("file_id")
					result.FilePath = row.String("file_path")
					return result
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return err
				}
				response.PreviousImageID = result.FileID
				response.PreviousImageName = path.Base(result.FilePath)
				return nil
			})
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				content, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
					},
				}, func(row *sq.Row) string {
					return row.String("text")
				})
				if err != nil {
					return err
				}
				response.Content = strings.TrimSpace(content)
				if strings.HasPrefix(response.Content, "!alt ") {
					altText, _, _ := strings.Cut(response.Content, "\n")
					response.AltText = strings.TrimSpace(strings.TrimPrefix(altText, "!alt "))
				}
				return nil
			})
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				extFilter := sq.Expr("1 <> 1")
				if len(imgExts) > 0 {
					var b strings.Builder
					args := make([]any, 0, len(imgExts))
					b.WriteString("(")
					for i, ext := range imgExts {
						if i > 0 {
							b.WriteString(" OR ")
						}
						b.WriteString("file_path LIKE {} ESCAPE '\\'")
						args = append(args, "%"+wildcardReplacer.Replace(ext))
					}
					b.WriteString(")")
					extFilter = sq.Expr(b.String(), args...)
				}
				result, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND file_path > {filePath}" +
						" AND {extFilter}" +
						" ORDER BY file_path ASC" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(response.SitePrefix, path.Dir(response.FilePath))),
						sq.StringParam("filePath", path.Join(response.SitePrefix, response.FilePath)),
						sq.Param("extFilter", extFilter),
					},
				}, func(row *sq.Row) (result struct {
					FileID   ID
					FilePath string
				}) {
					result.FileID = row.UUID("file_id")
					result.FilePath = row.String("file_path")
					return result
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return err
				}
				response.NextImageID = result.FileID
				response.NextImageName = path.Base(result.FilePath)
				return nil
			})
			err = group.Wait()
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		head, tail, _ := strings.Cut(filePath, "/")
		if head == "output" {
			next, _, _ := strings.Cut(tail, "/")
			if next == "posts" {
				response.URL = template.URL(response.ContentBaseURL + "/" + path.Dir(tail) + "/")
				response.BelongsTo = path.Dir(tail) + ".md"
			} else if next != "themes" {
				dir := path.Dir(tail)
				if dir == "." {
					response.URL = template.URL(response.ContentBaseURL)
					response.BelongsTo = "pages/index.html"
				} else {
					response.URL = template.URL(response.ContentBaseURL + "/" + path.Join("pages", dir) + "/")
					response.BelongsTo = path.Join("pages", dir+".html")
				}
			}
		}
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
				nbrew.GetLogger(r.Context()).Error(err.Error())
			}
			return
		}
		referer := nbrew.GetReferer(r)
		funcMap := map[string]any{
			"join":                  path.Join,
			"dir":                   path.Dir,
			"base":                  path.Base,
			"ext":                   path.Ext,
			"hasPrefix":             strings.HasPrefix,
			"hasSuffix":             strings.HasSuffix,
			"trimPrefix":            strings.TrimPrefix,
			"trimSuffix":            strings.TrimSuffix,
			"humanReadableFileSize": HumanReadableFileSize,
			"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
			"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
			"referer":               func() string { return referer },
			"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
		}
		tmpl, err := template.New("image.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/image.html")
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.ExecuteTemplate(w, r, tmpl, &response)
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
					nbrew.GetLogger(r.Context()).Error(err.Error())
				}
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from": "image",
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, filePath), http.StatusFound)
		}

		response := Response{}
		databaseFS, ok := &DatabaseFS{}, false
		switch v := nbrew.FS.(type) {
		case interface{ As(any) bool }:
			ok = v.As(&databaseFS)
		}
		if !ok {
			writeResponse(w, r, response)
			return
		}

		var request struct {
			Content            string
			RegeneratePostList bool
			RegenerateSite     bool
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&request)
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
			request.Content = r.Form.Get("content")
			request.RegeneratePostList, _ = strconv.ParseBool(r.Form.Get("regeneratePostList"))
			request.RegenerateSite, _ = strconv.ParseBool(r.Form.Get("regenerateSite"))
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response.Content = strings.TrimSpace(request.Content)
		_, err := sq.Exec(r.Context(), databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "UPDATE files SET text = {content}, mod_time = {modTime} WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("content", response.Content),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		head, tail, _ := strings.Cut(filePath, "/")
		if head == "output" {
			next, _, _ := strings.Cut(tail, "/")
			if next == "themes" {
				if request.RegenerateSite {
					regenerationStats, err := nbrew.RegenerateSite(r.Context(), sitePrefix)
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					response.RegenerationStats = regenerationStats
				}
			} else if next == "posts" {
				siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
					FS:                 nbrew.FS,
					ContentDomain:      nbrew.ContentDomain,
					ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
					CDNDomain:          nbrew.CDNDomain,
					SitePrefix:         sitePrefix,
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				var count atomic.Int64
				var templateErrPtr atomic.Pointer[TemplateError]
				group, groupctx := errgroup.WithContext(r.Context())
				response.BelongsTo = path.Dir(tail) + ".md"
				category := path.Dir(strings.TrimPrefix(response.BelongsTo, "posts/"))
				if category == "." {
					category = ""
				}
				startedAt := time.Now()
				group.Go(func() (err error) {
					defer func() {
						if v := recover(); v != nil {
							err = fmt.Errorf("panic: " + string(debug.Stack()))
						}
					}()
					var text string
					var creationTime time.Time
					databaseFS, ok := &DatabaseFS{}, false
					switch v := nbrew.FS.(type) {
					case interface{ As(any) bool }:
						ok = v.As(&databaseFS)
					}
					if ok {
						result, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
							Dialect: databaseFS.Dialect,
							Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
							Values: []any{
								sq.StringParam("filePath", path.Join(sitePrefix, response.BelongsTo)),
							},
						}, func(row *sq.Row) (result struct {
							Text         string
							CreationTime time.Time
						}) {
							result.Text = row.String("text")
							result.CreationTime = row.Time("creation_time")
							return result
						})
						if err != nil {
							return err
						}
						text = result.Text
						creationTime = result.CreationTime
					} else {
						file, err := nbrew.FS.WithContext(groupctx).Open(path.Join(sitePrefix, response.BelongsTo))
						if err != nil {
							return err
						}
						defer file.Close()
						fileInfo, err := file.Stat()
						if err != nil {
							return err
						}
						var b strings.Builder
						b.Grow(int(fileInfo.Size()))
						_, err = io.Copy(&b, file)
						if err != nil {
							return err
						}
						var absolutePath string
						switch v := nbrew.FS.(type) {
						case interface{ As(any) bool }:
							var directoryFS *DirectoryFS
							if v.As(&directoryFS) {
								absolutePath = path.Join(directoryFS.RootDir, sitePrefix, response.BelongsTo)
							}
						}
						text = b.String()
						creationTime = CreationTime(absolutePath, fileInfo)
					}
					tmpl, err := siteGen.PostTemplate(groupctx, category)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					err = siteGen.GeneratePost(groupctx, response.BelongsTo, text, time.Now(), creationTime, tmpl)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					count.Add(1)
					return nil
				})
				if request.RegeneratePostList {
					group.Go(func() (err error) {
						defer func() {
							if v := recover(); v != nil {
								err = fmt.Errorf("panic: " + string(debug.Stack()))
							}
						}()
						tmpl, err := siteGen.PostListTemplate(groupctx, category)
						if err != nil {
							var templateErr TemplateError
							if errors.As(err, &templateErr) {
								templateErrPtr.CompareAndSwap(nil, &templateErr)
								return nil
							}
							return err
						}
						n, err := siteGen.GeneratePostList(groupctx, category, tmpl)
						if err != nil {
							var templateErr TemplateError
							if errors.As(err, &templateErr) {
								templateErrPtr.CompareAndSwap(nil, &templateErr)
								return nil
							}
							return err
						}
						count.Add(n)
						return nil
					})
				}
				err = group.Wait()
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.RegenerationStats.Count = count.Load()
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				if ptr := templateErrPtr.Load(); ptr != nil {
					response.RegenerationStats.TemplateError = *ptr
				}
			} else {
				siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
					FS:                 nbrew.FS,
					ContentDomain:      nbrew.ContentDomain,
					ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
					CDNDomain:          nbrew.CDNDomain,
					SitePrefix:         sitePrefix,
				})
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				var text string
				var modTime, creationTime time.Time
				dir := path.Dir(tail)
				if dir == "." {
					response.BelongsTo = "pages/index.html"
				} else {
					response.BelongsTo = path.Join("pages", path.Dir(tail)+".html")
				}
				databaseFS, ok := &DatabaseFS{}, false
				switch v := nbrew.FS.(type) {
				case interface{ As(any) bool }:
					ok = v.As(&databaseFS)
				}
				if ok {
					result, err := sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
						Values: []any{
							sq.StringParam("filePath", path.Join(sitePrefix, response.BelongsTo)),
						},
					}, func(row *sq.Row) (result struct {
						Text         string
						ModTime      time.Time
						CreationTime time.Time
					}) {
						result.Text = row.String("text")
						result.ModTime = row.Time("mod_time")
						result.CreationTime = row.Time("creation_time")
						return result
					})
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					text = result.Text
					modTime = result.ModTime
					creationTime = result.CreationTime
				} else {
					file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, response.BelongsTo))
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					defer file.Close()
					fileInfo, err := file.Stat()
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						nbrew.GetLogger(r.Context()).Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
					text = b.String()
					modTime = fileInfo.ModTime()
					var absolutePath string
					switch v := nbrew.FS.(type) {
					case interface{ As(any) bool }:
						var directoryFS *DirectoryFS
						if v.As(&directoryFS) {
							absolutePath = path.Join(directoryFS.RootDir, response.SitePrefix, response.BelongsTo)
						}
					}
					creationTime = CreationTime(absolutePath, fileInfo)
				}
				startedAt := time.Now()
				err = siteGen.GeneratePage(r.Context(), response.BelongsTo, text, modTime, creationTime)
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				response.RegenerationStats.Count = 1
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
			}
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
