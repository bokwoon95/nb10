package nb10

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) image(w http.ResponseWriter, r *http.Request, user User, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		SitePrefix        string            `json:"sitePrefix"`
		ImgDomain         string            `json:"imgDomain"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		FileID            ID                `json:"fileID"`
		FilePath          string            `json:"filePath"`
		IsDir             bool              `json:"isDir"`
		Size              int64             `json:"size"`
		ModTime           time.Time         `json:"modTime"`
		CreationTime      time.Time         `json:"creationTime"`
		Content           string            `json:"content"`
		AltText           string            `json:"altText"`
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
					nbrew.notFound(w, r)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			defer file.Close()
			fileType, ok := fileTypes[path.Ext(filePath)]
			if !ok {
				nbrew.notFound(w, r)
				return
			}
			serveFile(w, r, file, fileInfo, fileType, "max-age=2592000, stale-while-revalidate=31536000" /* 1 month, 1 year */)
			return
		}
		var response Response
		_, err := nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentBaseURL = nbrew.contentBaseURL(sitePrefix)
		response.SitePrefix = sitePrefix
		response.ImgDomain = nbrew.ImgDomain
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
		response.FilePath = filePath
		response.Size = fileInfo.Size()
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
			response.IsDatabaseFS = true
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				result, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND file_path < {filePath}" +
						" AND (" +
						"file_path LIKE '%.jpeg'" +
						" OR file_path LIKE '%.jpg'" +
						" OR file_path LIKE '%.png'" +
						" OR file_path LIKE '%.webp'" +
						" OR file_path LIKE '%.gif'" +
						")" +
						" ORDER BY file_path DESC" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(response.SitePrefix, path.Dir(response.FilePath))),
						sq.StringParam("filePath", path.Join(response.SitePrefix, response.FilePath)),
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
			group.Go(func() error {
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
			group.Go(func() error {
				result, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
						" AND file_path > {filePath}" +
						" AND (" +
						"file_path LIKE '%.jpeg'" +
						" OR file_path LIKE '%.jpg'" +
						" OR file_path LIKE '%.png'" +
						" OR file_path LIKE '%.webp'" +
						" OR file_path LIKE '%.gif'" +
						")" +
						" ORDER BY file_path ASC" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("parent", path.Join(response.SitePrefix, path.Dir(response.FilePath))),
						sq.StringParam("filePath", path.Join(response.SitePrefix, response.FilePath)),
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
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		}
		head, tail, _ := strings.Cut(filePath, "/")
		if head == "output" {
			next, _, _ := strings.Cut(tail, "/")
			if next == "posts" {
				response.BelongsTo = path.Dir(tail) + ".md"
			} else if next != "themes" {
				response.BelongsTo = path.Join("pages", path.Dir(tail)+".html")
			}
		}
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
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.executeTemplate(w, r, tmpl, &response)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json")
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "image",
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, filePath), http.StatusFound)
		}

		response := Response{}
		databaseFS, ok := nbrew.FS.(*DatabaseFS)
		if !ok {
			writeResponse(w, r, response)
			return
		}

		var request struct {
			Content string
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&request)
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
			request.Content = r.Form.Get("content")
		default:
			nbrew.unsupportedContentType(w, r)
			return
		}

		response.Content = strings.TrimSpace(request.Content)
		_, err := sq.Exec(r.Context(), databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "UPDATE files SET text = {content} WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("content", response.Content),
				sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		head, tail, _ := strings.Cut(filePath, "/")
		if head == "output" {
			siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
				FS:                 nbrew.FS,
				ContentDomain:      nbrew.ContentDomain,
				ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
				ImgDomain:          nbrew.ImgDomain,
				SitePrefix:         sitePrefix,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			next, _, _ := strings.Cut(tail, "/")
			if next == "posts" {
				var text string
				var creationTime time.Time
				response.BelongsTo = path.Dir(tail) + ".md"
				if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
					result, err := sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
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
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					text = result.Text
					creationTime = result.CreationTime
				} else {
					file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, response.BelongsTo))
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					defer file.Close()
					fileInfo, err := file.Stat()
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					var absolutePath string
					if dirFS, ok := nbrew.FS.(*DirFS); ok {
						absolutePath = path.Join(dirFS.RootDir, sitePrefix, response.BelongsTo)
					}
					text = b.String()
					creationTime = CreationTime(absolutePath, fileInfo)
				}
				category := path.Dir(strings.TrimPrefix(response.BelongsTo, "posts/"))
				startedAt := time.Now()
				tmpl, err := siteGen.PostTemplate(r.Context(), category)
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				err = siteGen.GeneratePost(r.Context(), response.BelongsTo, text, creationTime, tmpl)
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				response.RegenerationStats.Count = 1
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
			} else if next != "themes" {
				var text string
				response.BelongsTo = path.Join("pages", path.Dir(tail)+".html")
				if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
					text, err = sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
						Values: []any{
							sq.StringParam("filePath", path.Join(sitePrefix, response.BelongsTo)),
						},
					}, func(row *sq.Row) string {
						return row.String("text")
					})
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
				} else {
					file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, response.BelongsTo))
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					defer file.Close()
					fileInfo, err := file.Stat()
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					text = b.String()
				}
				startedAt := time.Now()
				err = siteGen.GeneratePage(r.Context(), response.BelongsTo, text)
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				response.RegenerationStats.Count = 1
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
			}
		}
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
