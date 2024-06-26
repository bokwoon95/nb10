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

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) imports(w http.ResponseWriter, r *http.Request, user User, sitePrefix, fileName string) {
	type File struct {
		FileID       ID        `json:"fileID"`
		Parent       string    `json:"parent"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
	}
	type ImportJob struct {
		ImportJobID    ID        `json:"importJobID"`
		FileName       string    `json:"fileName"`
		StartTime      time.Time `json:"startTime"`
		TotalBytes     int64     `json:"totalBytes"`
		ProcessedBytes int64     `json:"processedBytes"`
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
		ImportJobs      []ImportJob    `json:"importJobs"`
		PinnedFiles     []File         `json:"pinnedfiles"`
		Files           []File         `json:"files"`
		PostRedirectGet map[string]any `json:"postRedirectGet"`
	}

	switch r.Method {
	case "GET", "HEAD":
		if fileName != "" {
			if strings.Contains(fileName, "/") || !strings.HasSuffix(fileName, ".tgz") {
				nbrew.notFound(w, r)
				return
			}
			file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, "imports", fileName))
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
			serveFile(w, r, fileName, fileInfo.Size(), fileTypes[".tgz"], file, "no-cache")
			return
		}
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
			}
			tmpl, err := template.New("imports.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/imports.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.executeTemplate(w, r, tmpl, &response)
		}

		fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "imports"))
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
		response.FilePath = "imports"
		response.IsDir = true

		group, groupctx := errgroup.WithContext(r.Context())
		if nbrew.DB != nil {
			group.Go(func() error {
				importJobs, err := sq.FetchAll(groupctx, nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format: "SELECT {*}" +
						" FROM import_job" +
						" WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName})" +
						" ORDER BY start_time DESC",
					Values: []any{
						sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
					},
				}, func(row *sq.Row) ImportJob {
					return ImportJob{
						ImportJobID:    row.UUID("import_job_id"),
						FileName:       row.String("file_name"),
						StartTime:      row.Time("start_time"),
						TotalBytes:     row.Int64("total_bytes"),
						ProcessedBytes: row.Int64("processed_bytes"),
					}
				})
				if err != nil {
					return err
				}
				response.ImportJobs = importJobs
				return nil
			})
		}
		if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
			group.Go(func() error {
				pinnedFiles, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM pinned_file" +
						" JOIN files ON files.file_id = pinned_file.file_id" +
						" WHERE pinned_file.parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" ORDER BY files.file_path",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, "imports")),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.PinnedFiles = pinnedFiles
				return nil
			})
			group.Go(func() error {
				files, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" ORDER BY file_path",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, "imports")),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.Files = files
				return nil
			})
		} else {
			group.Go(func() error {
				dirEntries, err := nbrew.FS.WithContext(groupctx).ReadDir(path.Join(sitePrefix, "imports"))
				if err != nil {
					return err
				}
				response.Files = make([]File, 0, len(dirEntries))
				for _, dirEntry := range dirEntries {
					fileInfo, err := dirEntry.Info()
					if err != nil {
						return err
					}
					name := fileInfo.Name()
					var absolutePath string
					if dirFS, ok := nbrew.FS.(*DirFS); ok {
						absolutePath = path.Join(dirFS.RootDir, sitePrefix, "imports", name)
					}
					file := File{
						Parent:       path.Join(sitePrefix, "imports"),
						Name:         name,
						IsDir:        fileInfo.IsDir(),
						Size:         fileInfo.Size(),
						ModTime:      fileInfo.ModTime(),
						CreationTime: CreationTime(absolutePath, fileInfo),
					}
					if file.IsDir {
						response.Files = append(response.Files, file)
						continue
					}
					_, ok := fileTypes[path.Ext(file.Name)]
					if !ok {
						continue
					}
					response.Files = append(response.Files, file)
				}
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
	case "POST":
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
