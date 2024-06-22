package nb10

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
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
	"strings"
	"sync/atomic"
	"time"

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
		Parent         string     `json:"parent"`
		Names          []string   `json:"names"`
		OutputName     string     `json:"outputName"`
		ExportParent   bool       `json:"exportParent"`
		Files          []File     `json:"files"`
		Error          string     `json:"error"`
		FormErrors     url.Values `json:"formErrors"`
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
		response.SitePrefix = sitePrefix
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))

		head, _, _ := strings.Cut(response.Parent, "/")
		switch head {
		case ".":
			response.ExportParent = true
			writeResponse(w, r, response)
			return
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
			response.ExportParent = len(r.Form["name"]) == 0
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}

		names := r.Form["name"]
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

		group, groupctx := errgroup.WithContext(r.Context())
		response.Files = make([]File, len(names))
		for i, name := range names {
			i, name := i, name
			group.Go(func() error {
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
		}
		err = group.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		n = 0
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
			if response.Error != "" {
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "export")+"/", http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "export",
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

		b, err := json.Marshal(map[string]any{
			"parent":     response.Parent,
			"names":      response.Names,
			"outputName": response.OutputName,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		source := string(b)

		parent := response.Parent
		names := response.Names
		if response.ExportParent {
			parent = path.Dir(response.Parent)
			names = []string{path.Base(response.Parent)}
		}

		// 1. prepare the row to be inserted
		// 2. attempt to acquire a slot (insert the row)
		// 3. if insertion fails with KeyViolation, then report to user that a job is already running
		var totalBytes atomic.Int64
		databaseFS, _ := nbrew.FS.(*DatabaseFS)
		group, groupctx := errgroup.WithContext(r.Context())
		for _, name := range names {
			name := name
			group.Go(func() error {
				root := path.Join(sitePrefix, parent, name)
				if databaseFS != nil {
					var filter sq.Expression
					if root == "." {
						filter = sq.Expr("(files.file_path LIKE 'notes/%'" +
							" OR files.file_path LIKE 'pages/%'" +
							" OR files.file_path LIKE 'posts/%'" +
							" OR files.file_path LIKE 'output/%'" +
							" OR files.parent_id IS NULL)")
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
		_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Debug:   true,
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO exports (site_id, file_name, source, start_time, total_bytes)" +
				" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), {fileName}, {source}, {startTime}, {totalBytes})",
			Values: []any{
				sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
				sq.StringParam("fileName", fileName),
				sq.StringParam("source", source),
				sq.TimeParam("startTime", startTime),
				sq.Int64Param("totalBytes", totalBytes.Load()),
			},
		})
		if err != nil {
			if nbrew.ErrorCode != nil {
				errorCode := nbrew.ErrorCode(err)
				if IsKeyViolation(nbrew.Dialect, errorCode) {
					response.Error = "there is an ongoing export, please try again once it has completed"
					writeResponse(w, r, response)
					return
				}
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}

		logger := getLogger(r.Context())
		nbrew.waitGroup.Add(1)
		go func() {
			defer nbrew.waitGroup.Done()
			nbrew.doExport(logger, sitePrefix, parent, names, fileName)
		}()
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}

type exportWriter struct {
	ctx            context.Context
	preparedExec   *sq.PreparedExec
	writer         io.Writer
	processedBytes int64
}

func (w *exportWriter) Write(p []byte) (n int, err error) {
	n, err = w.writer.Write(p)
	processedBytes := w.processedBytes + int64(n)
	if processedBytes%(1<<20) > w.processedBytes%(1<<20) {
		result, err := w.preparedExec.Exec(w.ctx, sq.Int64Param("processedBytes", processedBytes))
		if err != nil {
			return n, err
		}
		if result.RowsAffected == 0 {
			return n, fmt.Errorf("canceled from database: %w", context.Canceled)
		}
	}
	w.processedBytes = processedBytes
	return n, nil
}

func (nbrew *Notebrew) doExport(logger *slog.Logger, sitePrefix string, parent string, names []string, fileName string) {
	cleanup := func(exitErr error) {
		if errors.Is(exitErr, context.Canceled) || errors.Is(exitErr, context.DeadlineExceeded) {
			_, err := sq.Exec(context.Background(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "UPDATE exports SET start_time = NULL WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName})",
				Values: []any{
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
				},
			})
			if err != nil {
				logger.Error(err.Error())
			}
		} else {
			if exitErr != nil {
				logger.Error(exitErr.Error())
			}
			_, err := sq.Exec(context.Background(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "DELETE FROM exports WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName})",
				Values: []any{
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
				},
			})
			if err != nil {
				logger.Error(err.Error())
			}
		}
	}
	var db sq.DB
	if nbrew.Dialect == "sqlite" {
		db = nbrew.DB
	} else {
		conn, err := nbrew.DB.Conn(nbrew.ctx)
		if err != nil {
			cleanup(err)
			return
		}
		defer conn.Close()
		db = conn
	}
	preparedExec, err := sq.PrepareExec(nbrew.ctx, db, sq.Query{
		Dialect: nbrew.Dialect,
		Format:  "UPDATE exports SET processed_bytes = {processedBytes} WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName}) AND start_time IS NOT NULL",
		Values: []any{
			sq.Int64Param("processedBytes", 0),
			sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
		},
	})
	if err != nil {
		cleanup(err)
		return
	}
	defer preparedExec.Close()
	writer, err := nbrew.FS.WithContext(nbrew.ctx).OpenWriter(path.Join(sitePrefix, "exports", fileName), 0644)
	if err != nil {
		cleanup(err)
		return
	}
	defer writer.Close()
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(writer)
	defer func() {
		gzipWriter.Close()
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	tarWriter := tar.NewWriter(&exportWriter{
		ctx:          nbrew.ctx,
		preparedExec: preparedExec,
		writer:       gzipWriter,
	})
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
		for _, name := range names {
			root := path.Join(sitePrefix, parent, name)
			var filter sq.Expression
			if root == "." {
				filter = sq.Expr("file_path = 'notes' OR file_path LIKE 'notes/%'" +
					" OR file_path = 'pages' OR file_path LIKE 'pages/%'" +
					" OR file_path = 'posts' OR file_path LIKE 'posts/%'" +
					" OR file_path = 'output' OR file_path LIKE 'output/%'" +
					" OR file_path = 'site.json'")
			} else {
				filter = sq.Expr("file_path = {} OR file_path LIKE {} ESCAPE '\\'", root, wildcardReplacer.Replace(root)+"/%")
			}
			cursor, err := sq.FetchCursor(nbrew.ctx, databaseFS.DB, sq.Query{
				Debug:   true,
				Dialect: databaseFS.Dialect,
				Format:  "SELECT {*} FROM files WHERE {filter} ORDER BY file_path",
				Values: []any{
					sq.Param("filter", filter),
				},
			}, func(row *sq.Row) (file struct {
				FileID       ID
				FilePath     string
				IsDir        bool
				Size         int64
				ModTime      time.Time
				CreationTime time.Time
				Bytes        []byte
			}) {
				buf = row.Bytes(buf[:0], "COALESCE(text, data)")
				file.FileID = row.UUID("file_id")
				file.FilePath = row.String("file_path")
				file.IsDir = row.Bool("is_dir")
				file.Size = row.Int64("size")
				file.Bytes = buf
				file.ModTime = row.Time("mod_time")
				file.CreationTime = row.Time("creation_time")
				if sitePrefix != "" {
					file.FilePath = strings.TrimPrefix(strings.TrimPrefix(file.FilePath, sitePrefix), "/")
				}
				return file
			})
			if err != nil {
				cleanup(err)
				return
			}
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					cleanup(err)
					return
				}
				tarHeader := &tar.Header{
					Name:    file.FilePath,
					ModTime: file.ModTime,
					Size:    file.Size,
					PAXRecords: map[string]string{
						"NOTEBREW.file.creationTime": file.CreationTime.UTC().Format("2006-01-02 15:04:05Z"),
					},
				}
				if file.IsDir {
					tarHeader.Typeflag = tar.TypeDir
					tarHeader.Mode = 0755
					err = tarWriter.WriteHeader(tarHeader)
					if err != nil {
						cleanup(err)
						return
					}
					continue
				}
				fileType, ok := fileTypes[path.Ext(file.FilePath)]
				if !ok {
					continue
				}
				tarHeader.Typeflag = tar.TypeReg
				tarHeader.Mode = 0644
				err = tarWriter.WriteHeader(tarHeader)
				if err != nil {
					cleanup(err)
					return
				}
				if fileType.IsObject {
					reader, err := databaseFS.ObjectStorage.Get(nbrew.ctx, file.FileID.String()+path.Ext(file.FilePath))
					if err != nil {
						cleanup(err)
						return
					}
					_, err = io.Copy(tarWriter, reader)
					if err != nil {
						cleanup(err)
						return
					}
				} else {
					if fileType.IsGzippable && !IsFulltextIndexed(file.FilePath) {
						if gzipReader == nil {
							gzipReader, err = gzip.NewReader(bytes.NewReader(file.Bytes))
							if err != nil {
								cleanup(err)
								return
							}
						} else {
							err = gzipReader.Reset(bytes.NewReader(file.Bytes))
							if err != nil {
								cleanup(err)
								return
							}
						}
						_, err = io.Copy(tarWriter, gzipReader)
						if err != nil {
							cleanup(err)
							return
						}
					} else {
						_, err = io.Copy(tarWriter, bytes.NewReader(file.Bytes))
						if err != nil {
							cleanup(err)
							return
						}
					}
				}
			}
			err = cursor.Close()
			if err != nil {
				cleanup(err)
				return
			}
		}
	} else {
		fn := func(filePath string, dirEntry fs.DirEntry, err error) error {
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
			creationTime := CreationTime(absolutePath, fileInfo)
			tarHeader := &tar.Header{
				Name:    filePath,
				ModTime: fileInfo.ModTime(),
				Size:    fileInfo.Size(),
				PAXRecords: map[string]string{
					"NOTEBREW.file.creationTime": creationTime.UTC().Format("2006-01-02 15:04:05Z"),
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
			file, err := nbrew.FS.WithContext(nbrew.ctx).Open(filePath)
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
					err := fs.WalkDir(nbrew.FS.WithContext(nbrew.ctx), root, fn)
					if err != nil {
						cleanup(err)
						return
					}
				}
			} else {
				err := fs.WalkDir(nbrew.FS.WithContext(nbrew.ctx), root, fn)
				if err != nil {
					cleanup(err)
					return
				}
			}
		}
	}
	cleanup(nil)
}
