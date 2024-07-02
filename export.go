package nb10

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) export(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type File struct {
		FileID       ID        `json:"fileID"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		Size         int64     `json:"size"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
	}
	type Request struct {
		Parent     string   `json:"parent"`
		Names      []string `json:"names"`
		OutputName string   `json:"outputName"`
	}
	type Response struct {
		ContentBaseURL string     `json:"contentBaseURL"`
		ImgDomain      string     `json:"imgDomain"`
		IsDatabaseFS   bool       `json:"isDatabaseFS"`
		SitePrefix     string     `json:"sitePrefix"`
		UserID         ID         `json:"userID"`
		Username       string     `json:"username"`
		DisableReason  string     `json:"disableReason"`
		Parent         string     `json:"parent"`
		Names          []string   `json:"names"`
		OutputName     string     `json:"outputName"`
		ExportParent   bool       `json:"exportParent"`
		TotalBytes     int64      `json:"totalBytes"`
		Files          []File     `json:"files"`
		Error          string     `json:"error"`
		FormErrors     url.Values `json:"formErrors"`
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
			tmpl, err := template.New("export.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/export.html")
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
		response.DisableReason = user.DisableReason
		response.SitePrefix = sitePrefix
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		names := r.Form["name"]

		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case ".":
			response.ExportParent = true
		case "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					response.Error = "InvalidParent"
					writeResponse(w, r, response)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			if !fileInfo.IsDir() {
				response.Error = "InvalidParent"
				writeResponse(w, r, response)
				return
			}
			if len(names) == 0 {
				response.ExportParent = true
			} else {
				seen := make(map[string]bool)
				n := 0
				for _, name := range names {
					name := filepath.ToSlash(name)
					if strings.Contains(name, "/") {
						continue
					}
					if seen[name] {
						continue
					}
					seen[name] = true
					names[n] = name
					n++
				}
				names = names[:n]
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}

		if nbrew.DB != nil {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM export_job WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName})",
				Values: []any{
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			if exists {
				response.Error = "ExportLimitReached"
				writeResponse(w, r, response)
				return
			}
		}

		if response.ExportParent {
			root := path.Join(sitePrefix, response.Parent)
			if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
				var filter sq.Expression
				if root == "." {
					filter = sq.Expr("(files.file_path LIKE 'notes/%'" +
						" OR files.file_path LIKE 'pages/%'" +
						" OR files.file_path LIKE 'posts/%'" +
						" OR files.file_path LIKE 'output/%'" +
						" OR files.file_path = 'site.json')")
				} else {
					filter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(root)+"/%")
				}
				n, err := sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format:  "SELECT {*} FROM files WHERE {filter}",
					Values: []any{
						sq.Param("filter", filter),
					},
				}, func(row *sq.Row) int64 {
					return row.Int64("sum(coalesce(size, 0))")
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				response.TotalBytes = n
			} else {
				err := fs.WalkDir(nbrew.FS.WithContext(r.Context()), root, func(filePath string, dirEntry fs.DirEntry, err error) error {
					if err != nil {
						if errors.Is(err, fs.ErrNotExist) {
							return nil
						}
						return err
					}
					if dirEntry.IsDir() {
						return nil
					}
					fileInfo, err := dirEntry.Info()
					if err != nil {
						return err
					}
					response.TotalBytes += fileInfo.Size()
					return nil
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			}
			writeResponse(w, r, response)
			return
		}

		var totalBytes atomic.Int64
		group, groupctx := errgroup.WithContext(r.Context())
		response.Files = make([]File, len(names))
		for i, name := range names {
			i, name := i, name
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctx), path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				file := File{
					Name:    fileInfo.Name(),
					IsDir:   fileInfo.IsDir(),
					Size:    fileInfo.Size(),
					ModTime: fileInfo.ModTime(),
				}
				if fileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
					file.FileID = fileInfo.FileID
					file.CreationTime = fileInfo.CreationTime
				} else {
					var absolutePath string
					if dirFS, ok := nbrew.FS.(*DirFS); ok {
						absolutePath = path.Join(dirFS.RootDir, sitePrefix, response.Parent, name)
					}
					file.CreationTime = CreationTime(absolutePath, fileInfo)
				}
				response.Files[i] = file
				return nil
			})
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				root := path.Join(sitePrefix, response.Parent, name)
				if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
					var filter sq.Expression
					if root == "." {
						filter = sq.Expr("(files.file_path LIKE 'notes/%'" +
							" OR files.file_path LIKE 'pages/%'" +
							" OR files.file_path LIKE 'posts/%'" +
							" OR files.file_path LIKE 'output/%'" +
							" OR files.file_path = 'site.json')")
					} else {
						filter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(root)+"/%")
					}
					n, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format:  "SELECT {*} FROM files WHERE {filter}",
						Values: []any{
							sq.Param("filter", filter),
						},
					}, func(row *sq.Row) int64 {
						return row.Int64("sum(coalesce(size, 0))")
					})
					if err != nil {
						return err
					}
					totalBytes.Add(n)
				} else {
					err := fs.WalkDir(nbrew.FS.WithContext(groupctx), root, func(filePath string, dirEntry fs.DirEntry, err error) error {
						if err != nil {
							if errors.Is(err, fs.ErrNotExist) {
								return nil
							}
							return err
						}
						if dirEntry.IsDir() {
							return nil
						}
						fileInfo, err := dirEntry.Info()
						if err != nil {
							return err
						}
						totalBytes.Add(fileInfo.Size())
						return nil
					})
					if err != nil {
						return err
					}
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
		response.TotalBytes = totalBytes.Load()
		n := 0
		for _, file := range response.Files {
			if file.Name == "" {
				continue
			}
			response.Files[n] = file
			n++
		}
		response.Files = response.Files[:n]
		writeResponse(w, r, response)
	case "POST":
		if user.DisableReason != "" {
			nbrew.accountDisabled(w, r, user.DisableReason)
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
			if response.Error != "" {
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				values := url.Values{
					"parent": []string{response.Parent},
					"name":   response.Names,
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "export")+"/?"+values.Encode(), http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":     "export",
					"fileName": response.OutputName + ".tgz",
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "exports")+"/", http.StatusFound)
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
			request.Parent = r.Form.Get("parent")
			request.Names = r.Form["name"]
			request.OutputName = r.Form.Get("outputName")
		default:
			nbrew.unsupportedContentType(w, r)
			return
		}

		response := Response{
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Names:      make([]string, 0, len(request.Names)),
			OutputName: filenameSafe(request.OutputName),
			FormErrors: url.Values{},
		}
		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case ".":
			response.ExportParent = true
		case "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					response.Error = "InvalidParent"
					writeResponse(w, r, response)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			if !fileInfo.IsDir() {
				response.Error = "InvalidParent"
				writeResponse(w, r, response)
				return
			}
			if len(request.Names) == 0 {
				response.ExportParent = true
			} else {
				seen := make(map[string]bool)
				for _, name := range request.Names {
					name := filepath.ToSlash(name)
					if strings.Contains(name, "/") {
						continue
					}
					if seen[name] {
						continue
					}
					seen[name] = true
					response.Names = append(response.Names, name)
				}
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}

		startTime := time.Now().UTC()
		if response.OutputName == "" {
			response.OutputName = "files-" + strings.ReplaceAll(startTime.Format("2006-01-02-150405.999"), ".", "-")
		}
		fileName := response.OutputName + ".tgz"
		_, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "exports", fileName))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		} else {
			response.FormErrors.Add("outputName", "file name already exists")
			writeResponse(w, r, response)
			return
		}

		parent := response.Parent
		names := response.Names
		if response.ExportParent {
			parent = path.Dir(response.Parent)
			names = []string{path.Base(response.Parent)}
		}

		var totalBytes atomic.Int64
		group, groupctx := errgroup.WithContext(r.Context())
		for _, name := range names {
			name := name
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				root := path.Join(sitePrefix, parent, name)
				if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
					var filter sq.Expression
					if root == "." {
						filter = sq.Expr("(files.file_path LIKE 'notes/%'" +
							" OR files.file_path LIKE 'pages/%'" +
							" OR files.file_path LIKE 'posts/%'" +
							" OR files.file_path LIKE 'output/%'" +
							" OR files.file_path = 'site.json')")
					} else {
						filter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(root)+"/%")
					}
					n, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format:  "SELECT {*} FROM files WHERE {filter}",
						Values: []any{
							sq.Param("filter", filter),
						},
					}, func(row *sq.Row) int64 {
						return row.Int64("sum(coalesce(size, 0))")
					})
					if err != nil {
						return err
					}
					totalBytes.Add(n)
				} else {
					err := fs.WalkDir(nbrew.FS.WithContext(groupctx), root, func(filePath string, dirEntry fs.DirEntry, err error) error {
						if err != nil {
							if errors.Is(err, fs.ErrNotExist) {
								return nil
							}
							return err
						}
						if dirEntry.IsDir() {
							return nil
						}
						fileInfo, err := dirEntry.Info()
						if err != nil {
							return err
						}
						totalBytes.Add(fileInfo.Size())
						return nil
					})
					if err != nil {
						return err
					}
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
		// 1. prepare the row to be inserted
		// 2. attempt to acquire a slot (insert the row)
		// 3. if insertion fails with KeyViolation, then report to user that a job is already running
		exportJobID := NewID()
		response.TotalBytes = totalBytes.Load()
		if nbrew.DB == nil {
			err = nbrew.doExport(r.Context(), exportJobID, sitePrefix, parent, names, fileName)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		} else {
			_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO export_job (export_job_id, site_id, file_name, start_time, total_bytes)" +
					" VALUES ({exportJobID}, (SELECT site_id FROM site WHERE site_name = {siteName}), {fileName}, {startTime}, {totalBytes})",
				Values: []any{
					sq.UUIDParam("exportJobID", exportJobID),
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
					sq.StringParam("fileName", fileName),
					sq.TimeParam("startTime", startTime),
					sq.Int64Param("totalBytes", response.TotalBytes),
				},
			})
			if err != nil {
				if nbrew.ErrorCode != nil {
					errorCode := nbrew.ErrorCode(err)
					if IsKeyViolation(nbrew.Dialect, errorCode) {
						response.Error = "ExportLimitReached"
						writeResponse(w, r, response)
						return
					}
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			nbrew.waitGroup.Add(1)
			logger := getLogger(r.Context())
			requestURL := r.Method + " " + r.Host + r.URL.RequestURI()
			go func() {
				defer func() {
					if v := recover(); v != nil {
						fmt.Println("panic: " + requestURL + ":\n" + string(debug.Stack()))
					}
				}()
				defer nbrew.waitGroup.Done()
				err := nbrew.doExport(nbrew.ctx, exportJobID, sitePrefix, parent, names, fileName)
				if err != nil {
					logger.Error(err.Error(),
						slog.String("exportJobID", exportJobID.String()),
						slog.String("sitePrefix", sitePrefix),
						slog.String("parent", parent),
						slog.String("names", strings.Join(names, "|")),
						slog.String("fileName", fileName),
					)
				}
			}()
		}
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}

type progressWriter struct {
	ctx            context.Context
	writer         io.Writer
	preparedExec   *sq.PreparedExec
	processedBytes int64
}

func (w *progressWriter) Write(p []byte) (n int, err error) {
	err = w.ctx.Err()
	if err != nil {
		return 0, err
	}
	n, err = w.writer.Write(p)
	if w.preparedExec == nil {
		return n, err
	}
	processedBytes := w.processedBytes + int64(n)
	if processedBytes%(1<<20) > w.processedBytes%(1<<20) {
		result, err := w.preparedExec.Exec(w.ctx, sq.Int64Param("processedBytes", processedBytes))
		if err != nil {
			return n, err
		}
		// We weren't able to update the database row, which means it has been
		// deleted (i.e. job canceled).
		if result.RowsAffected == 0 {
			return n, fmt.Errorf("export canceled")
		}
	}
	w.processedBytes = processedBytes
	return n, err
}

func (nbrew *Notebrew) doExport(ctx context.Context, exportJobID ID, sitePrefix string, parent string, names []string, fileName string) error {
	success := false
	defer func() {
		if nbrew.DB == nil {
			return
		}
		_, err := sq.Exec(context.Background(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM export_job WHERE export_job_id = {exportJobID}",
			Values: []any{
				sq.UUIDParam("exportJobID", exportJobID),
			},
		})
		if err != nil {
			nbrew.Logger.Error(err.Error())
		}
		if !success {
			err := nbrew.FS.WithContext(context.Background()).Remove(path.Join(sitePrefix, "exports", fileName))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					nbrew.Logger.Error(err.Error())
				}
			}
		}
	}()
	writer, err := nbrew.FS.WithContext(ctx).OpenWriter(path.Join(sitePrefix, "exports", fileName), 0644)
	if err != nil {
		return err
	}
	defer writer.Close()
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(writer)
	defer func() {
		gzipWriter.Close()
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	var dest io.Writer
	if nbrew.DB == nil {
		dest = gzipWriter
	} else {
		var db sq.DB
		if nbrew.Dialect == "sqlite" {
			db = nbrew.DB
		} else {
			var conn *sql.Conn
			conn, err = nbrew.DB.Conn(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			db = conn
		}
		preparedExec, err := sq.PrepareExec(ctx, db, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "UPDATE export_job SET processed_bytes = {processedBytes} WHERE export_job_id = {exportJobID}",
			Values: []any{
				sq.Int64Param("processedBytes", 0),
				sq.UUIDParam("exportJobID", exportJobID),
			},
		})
		if err != nil {
			return err
		}
		defer preparedExec.Close()
		dest = &progressWriter{
			ctx:            ctx,
			writer:         gzipWriter,
			preparedExec:   preparedExec,
			processedBytes: 0,
		}
	}
	tarWriter := tar.NewWriter(dest)
	defer tarWriter.Close()
	if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
		buf := bufPool.Get().(*bytes.Buffer).Bytes()
		defer func() {
			if cap(buf) <= maxPoolableBufferCapacity {
				buf = buf[:0]
				bufPool.Put(bytes.NewBuffer(buf))
			}
		}()
		gzipReader, _ := gzipReaderPool.Get().(*gzip.Reader)
		defer func() {
			if gzipReader != nil {
				gzipReader.Reset(empty)
				gzipReaderPool.Put(gzipReader)
			}
		}()
		type File struct {
			FileID       ID
			FilePath     string
			IsDir        bool
			Size         int64
			ModTime      time.Time
			CreationTime time.Time
			Bytes        []byte
			IsPinned     bool
		}
		for _, name := range names {
			root := path.Join(sitePrefix, parent, name)
			var filter sq.Expression
			if root == "." {
				filter = sq.Expr("files.file_path = 'notes' OR files.file_path LIKE 'notes/%'" +
					" OR files.file_path = 'pages' OR files.file_path LIKE 'pages/%'" +
					" OR files.file_path = 'posts' OR files.file_path LIKE 'posts/%'" +
					" OR files.file_path = 'output' OR files.file_path LIKE 'output/%'" +
					" OR files.file_path = 'site.json'")
			} else {
				filter = sq.Expr("files.file_path = {} OR files.file_path LIKE {} ESCAPE '\\'", root, wildcardReplacer.Replace(root)+"/%")
			}
			cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" LEFT JOIN pinned_file ON pinned_file.parent_id = files.parent_id AND pinned_file.file_id = files.file_id" +
					" WHERE {filter}" +
					" ORDER BY files.file_path",
				Values: []any{
					sq.Param("filter", filter),
				},
			}, func(row *sq.Row) (file File) {
				buf = row.Bytes(buf[:0], "COALESCE(files.text, files.data)")
				file.FileID = row.UUID("files.file_id")
				file.FilePath = row.String("files.file_path")
				file.IsDir = row.Bool("files.is_dir")
				file.Size = row.Int64("files.size")
				file.Bytes = buf
				file.ModTime = row.Time("files.mod_time")
				file.CreationTime = row.Time("files.creation_time")
				file.IsPinned = row.Bool("pinned_file.file_id IS NOT NULL")
				if sitePrefix != "" {
					file.FilePath = strings.TrimPrefix(strings.TrimPrefix(file.FilePath, sitePrefix), "/")
				}
				return file
			})
			if err != nil {
				return err
			}
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					return err
				}
				head, _, _ := strings.Cut(file.FilePath, "/")
				if head != "notes" && head != "pages" && head != "posts" && head != "output" && file.FilePath != "site.json" {
					continue
				}
				tarHeader := &tar.Header{
					Name:    file.FilePath,
					ModTime: file.ModTime,
					Size:    file.Size,
					PAXRecords: map[string]string{
						"NOTEBREW.file.modTime":      file.ModTime.UTC().Format("2006-01-02T15:04:05Z"),
						"NOTEBREW.file.creationTime": file.CreationTime.UTC().Format("2006-01-02T15:04:05Z"),
					},
				}
				if file.IsPinned {
					tarHeader.PAXRecords["NOTEBREW.file.isPinned"] = "true"
				}
				if file.IsDir {
					tarHeader.Typeflag = tar.TypeDir
					tarHeader.Mode = 0755
					err = tarWriter.WriteHeader(tarHeader)
					if err != nil {
						return err
					}
					continue
				}
				fileType, ok := fileTypes[path.Ext(file.FilePath)]
				if !ok {
					continue
				}
				switch fileType.Ext {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					if len(file.Bytes) > 0 && utf8.Valid(file.Bytes) {
						tarHeader.PAXRecords["NOTEBREW.file.caption"] = string(file.Bytes)
					}
				}
				tarHeader.Typeflag = tar.TypeReg
				tarHeader.Mode = 0644
				err = tarWriter.WriteHeader(tarHeader)
				if err != nil {
					return err
				}
				if fileType.IsObject {
					reader, err := databaseFS.ObjectStorage.Get(ctx, file.FileID.String()+path.Ext(file.FilePath))
					if err != nil {
						return err
					}
					_, err = io.Copy(tarWriter, reader)
					if err != nil {
						return err
					}
					err = reader.Close()
					if err != nil {
						return err
					}
				} else {
					if fileType.IsGzippable && !IsFulltextIndexed(file.FilePath) {
						if gzipReader == nil {
							gzipReader, err = gzip.NewReader(bytes.NewReader(file.Bytes))
							if err != nil {
								return err
							}
						} else {
							err = gzipReader.Reset(bytes.NewReader(file.Bytes))
							if err != nil {
								return err
							}
						}
						_, err = io.Copy(tarWriter, gzipReader)
						if err != nil {
							return err
						}
					} else {
						_, err = io.Copy(tarWriter, bytes.NewReader(file.Bytes))
						if err != nil {
							return err
						}
					}
				}
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
		}
	} else {
		walkDirFunc := func(filePath string, dirEntry fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			fileInfo, err := dirEntry.Info()
			if err != nil {
				return err
			}
			var absolutePath string
			if dirFS, ok := nbrew.FS.(*DirFS); ok {
				absolutePath = path.Join(dirFS.RootDir, filePath)
			}
			modTime := fileInfo.ModTime()
			creationTime := CreationTime(absolutePath, fileInfo)
			tarHeader := &tar.Header{
				Name:    filePath,
				ModTime: modTime,
				Size:    fileInfo.Size(),
				PAXRecords: map[string]string{
					"NOTEBREW.file.modTime":      modTime.UTC().Format("2006-01-02T15:04:05Z"),
					"NOTEBREW.file.creationTime": creationTime.UTC().Format("2006-01-02T15:04:05Z"),
				},
			}
			if dirEntry.IsDir() {
				tarHeader.Typeflag = tar.TypeDir
				tarHeader.Mode = 0755
				err = tarWriter.WriteHeader(tarHeader)
				if err != nil {
					return err
				}
				return nil
			}
			_, ok := fileTypes[path.Ext(filePath)]
			if !ok {
				return nil
			}
			tarHeader.Typeflag = tar.TypeReg
			tarHeader.Mode = 0644
			err = tarWriter.WriteHeader(tarHeader)
			if err != nil {
				return err
			}
			file, err := nbrew.FS.WithContext(ctx).Open(filePath)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tarWriter, file)
			if err != nil {
				return err
			}
			return nil
		}
		for _, name := range names {
			root := path.Join(sitePrefix, parent, name)
			if root == "." {
				for _, root := range []string{"notes", "pages", "posts", "output", "site.json"} {
					err = fs.WalkDir(nbrew.FS.WithContext(ctx), root, walkDirFunc)
					if err != nil {
						return err
					}
				}
			} else {
				err = fs.WalkDir(nbrew.FS.WithContext(ctx), root, walkDirFunc)
				if err != nil {
					return err
				}
			}
		}
	}
	err = tarWriter.Close()
	if err != nil {
		return err
	}
	err = gzipWriter.Close()
	if err != nil {
		return err
	}
	err = writer.Close()
	if err != nil {
		return err
	}
	success = true
	return nil
}
