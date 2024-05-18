package nb10

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
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
		Parent string   `json:"parent"`
		Names  []string `json:"names"`
	}
	type Response struct {
		ContentBaseURL string     `json:"contentBaseURL"`
		ImgDomain      string     `json:"imgDomain"`
		IsDatabaseFS   bool       `json:"isDatabaseFS"`
		SitePrefix     string     `json:"sitePrefix"`
		UserID         ID         `json:"userID"`
		Username       string     `json:"username"`
		Parent         string     `json:"parent"`
		Files          []File     `json:"files"`
		ExportParent   bool       `json:"exportParent"`
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
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}

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
		response.ExportParent = len(names) == 0
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
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
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
		default:
			nbrew.unsupportedContentType(w, r)
			return
		}

		response := Response{
			Parent:     request.Parent,
			FormErrors: url.Values{},
			Files:      make([]File, 0, len(request.Names)),
		}
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
			response.Files = append(response.Files, File{
				Name: name,
			})
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
			response.ExportParent = len(request.Names) == 0
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}

		var totalBytes atomic.Int64
		_ = &totalBytes
		if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
			_ = databaseFS
			if response.ExportParent {
				// TODO: just get the total size of the parent, no need to loop the names
			} else {
			}
			group, groupctx := errgroup.WithContext(r.Context())
			_ = groupctx
			for i, name := range request.Names {
				i, name := i, name
				_, _ = i, name
				group.Go(func() error {
					var parentFilter sq.Expression
					_ = parentFilter
					parent := path.Join(sitePrefix, response.Parent, name)
					if parent == "." {
						parentFilter = sq.Expr("(files.file_path LIKE 'notes/%'" +
							" OR files.file_path LIKE 'pages/%'" +
							" OR files.file_path LIKE 'posts/%'" +
							" OR files.file_path LIKE 'output/%'" +
							" OR files.parent_id IS NULL)")
					} else {
						parentFilter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(parent)+"/%")
					}
					return nil
				})
			}
		} else {
		}

		// 1. prepare the row to be inserted
		// 2. attempt to acquire a slot (insert the row)
		// 3. if insertion fails with KeyViolation, then report to user that a job is already running
	default:
		nbrew.methodNotAllowed(w, r)
	}
}

func (nbrew *Notebrew) export_OldV2(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	if r.Method != "GET" {
		nbrew.methodNotAllowed(w, r)
		return
	}
	responseController := http.NewResponseController(w)
	err := responseController.SetWriteDeadline(time.Now().Add(time.Hour))
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}

	var fileName string
	if sitePrefix == "" {
		fileName = "files-" + time.Now().UTC().Format("20060102150405") + ".tgz"
	} else {
		fileName = "files-" + strings.TrimPrefix(sitePrefix, "@") + "-" + time.Now().UTC().Format("20060102150405") + ".tgz"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fileName+`"`)

	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(bufio.NewWriter(w))
	defer func() {
		gzipWriter.Close()
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
	if parent != "." {
		head, _, _ := strings.Cut(parent, "/")
		switch head {
		case "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, parent))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return
				}
				getLogger(r.Context()).Error(err.Error())
				return
			}
			if !fileInfo.IsDir() {
				return
			}
		default:
			return
		}
	}

	names := r.Form["name"]
	seen := make(map[string]bool)
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
			if seen[name] {
				continue
			}
			seen[name] = true
			cursor, err := sq.FetchCursor(r.Context(), databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format:  "SELECT {*} FROM files WHERE file_path = {filePath} OR file_path LIKE {pattern} ESCAPE '\\' ORDER BY file_path",
				Values: []any{
					sq.Param("filePath", path.Join(sitePrefix, parent, name)),
					sq.Param("pattern", wildcardReplacer.Replace(path.Join(sitePrefix, parent, name))+"/%"),
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
				getLogger(r.Context()).Error(err.Error())
				return
			}
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					return
				}
				fileType, ok := fileTypes[path.Ext(file.FilePath)]
				if !ok {
					continue
				}
				fmt.Printf("dumping: %s\n", file.FilePath)
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
				} else {
					tarHeader.Typeflag = tar.TypeReg
					tarHeader.Mode = 0644
				}
				tarWriter.WriteHeader(tarHeader)
				if fileType.IsObject {
					reader, err := databaseFS.ObjectStorage.Get(r.Context(), file.FileID.String()+path.Ext(file.FilePath))
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						return
					}
					_, err = io.Copy(tarWriter, reader)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						return
					}
				} else {
					if fileType.IsGzippable && !IsFulltextIndexed(file.FilePath) {
						if gzipReader == nil {
							gzipReader, err = gzip.NewReader(bytes.NewReader(file.Bytes))
							if err != nil {
								getLogger(r.Context()).Error(err.Error())
								return
							}
						} else {
							err = gzipReader.Reset(bytes.NewReader(file.Bytes))
							if err != nil {
								getLogger(r.Context()).Error(err.Error())
								return
							}
						}
						_, err = io.Copy(tarWriter, gzipReader)
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							return
						}
					} else {
						_, err = io.Copy(tarWriter, bytes.NewReader(file.Bytes))
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							return
						}
					}
				}
			}
			err = cursor.Close()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				return
			}
		}
	} else {
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
		}
	}
}

func (nbrew *Notebrew) export_Old(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Response struct {
		ContentBaseURL string   `json:"contentBaseURL"`
		ImgDomain      string   `json:"imgDomain"`
		IsDatabaseFS   bool     `json:"isDatabaseFS"`
		SitePrefix     string   `json:"sitePrefix"`
		UserID         ID       `json:"userID"`
		Username       string   `json:"username"`
		Parent         string   `json:"parent"`
		Names          []string `json:"names"`
		Error          string   `json:"error"`
		Size           int64    `json:"size"`
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		nbrew.methodNotAllowed(w, r)
		return
	}

	if !r.Form.Has("confirm") {
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
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}

		seen := make(map[string]bool)
		group, groupctx := errgroup.WithContext(r.Context())
		names := r.Form["name"]
		_, _, _, _ = seen, group, groupctx, names
		writeResponse(w, r, response)
		return
	}

	if true {
		http.Error(w, "TODO", http.StatusNotImplemented)
		return
	}

	parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
	if parent != "." {
		head, _, _ := strings.Cut(parent, "/")
		switch head {
		case "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, parent))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					http.Error(w, "InvalidParent", http.StatusBadRequest)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			if !fileInfo.IsDir() {
				http.Error(w, "InvalidParent", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "InvalidParent", http.StatusBadRequest)
			return
		}
	}
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(w)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()
	var fileName string
	if sitePrefix == "" {
		fileName = "files-" + time.Now().UTC().Format("20060102150405") + ".tgz"
	} else {
		fileName = "files-" + strings.TrimPrefix(sitePrefix, "@") + "-" + time.Now().UTC().Format("20060102150405") + ".tgz"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fileName+`"`)
	gzipReader, _ := gzipReaderPool.Get().(*gzip.Reader)
	defer func() {
		if gzipReader != nil {
			gzipReader.Reset(empty)
			gzipReaderPool.Put(gzipReader)
		}
	}()
	b := bufPool.Get().(*bytes.Buffer).Bytes()
	defer func() {
		if cap(b) <= maxPoolableBufferCapacity {
			b = b[:0]
			bufPool.Put(bytes.NewBuffer(b))
		}
	}()
	databaseFS, ok := nbrew.FS.(*DatabaseFS)
	if !ok || true {
		subFS, err := fs.Sub(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, parent))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		// TODO: we cannot use AddFS, we want to custom encode CreationTime in
		// a PaxRecord (so that it can be imported).
		err = tarWriter.AddFS(subFS)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		err = tarWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		return
	}
	if ok && false {
		cursor, err := sq.FetchCursor(r.Context(), databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path LIKE {pattern} ESCAPE '\\' ORDER BY file_path",
			Values: []any{
				sq.Param("pattern", wildcardReplacer.Replace(path.Join(sitePrefix, parent))+"/%"),
			},
		}, func(row *sq.Row) (file struct {
			FileID       ID
			FilePath     string
			IsDir        bool
			ModTime      time.Time
			CreationTime time.Time
			Bytes        []byte
		}) {
			b = row.Bytes(b[:0], "COALESCE(text, data)")
			file.FileID = row.UUID("file_id")
			file.FilePath = row.String("file_path")
			file.IsDir = row.Bool("is_dir")
			file.Bytes = b
			if sitePrefix != "" {
				file.FilePath = strings.TrimPrefix(strings.TrimPrefix(file.FilePath, sitePrefix), "/")
			}
			return file
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		defer cursor.Close()
		for cursor.Next() {
		}
		err = cursor.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		// TODO: if we want to avoid the N+1 problems arising from calling
		// fs.WalkDir, we'll need to walk the rows ourselves and uncompress
		// gzippable files and fetching objects from ObjectStorage
		// accordingly.
	}
}

func (nbrew *Notebrew) runExportJob(ctx context.Context, sitePrefix, fileName, parent string, names []string) {
	defer func() {
		if r := recover(); r != nil {
			if nbrew.DB == nil {
				nbrew.exportJobMutex.Lock()
				delete(nbrew.exportJob, sitePrefix)
				nbrew.exportJobMutex.Unlock()
				return
			}
			_, err := sq.Exec(context.Background(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "DELETE FROM export_job WHERE site_prefix = {sitePrefix}",
				Values: []any{
					sq.StringParam("sitePrefix", sitePrefix),
				},
			})
			if err != nil {
				nbrew.Logger.Error(err.Error())
			}
		}
	}()
	cleanup := func(exitErr error) {
		if errors.Is(exitErr, context.Canceled) || errors.Is(exitErr, context.DeadlineExceeded) {
			if nbrew.DB == nil {
				return
			}
			// status: started | restart
			_, err := sq.Exec(context.Background(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "UPDATE export_job SET status = 'restart' WHERE site_prefix = {sitePrefix}",
				Values: []any{
					sq.StringParam("sitePrefix", sitePrefix),
				},
			})
			if err != nil {
				nbrew.Logger.Error(err.Error())
			}
			return
		}
		if exitErr != nil {
			nbrew.Logger.Error(exitErr.Error())
		}
		if nbrew.DB == nil {
			nbrew.exportJobMutex.Lock()
			delete(nbrew.exportJob, sitePrefix)
			nbrew.exportJobMutex.Unlock()
			return
		}
		_, err := sq.Exec(context.Background(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM export_job WHERE site_prefix = {sitePrefix}",
			Values: []any{
				sq.StringParam("sitePrefix", sitePrefix),
			},
		})
		if err != nil {
			nbrew.Logger.Error(err.Error())
		}
	}
	writer, err := nbrew.FS.WithContext(ctx).OpenWriter(path.Join(sitePrefix, "exports", fileName), 0644)
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
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()
	seen := make(map[string]bool)
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
			if seen[name] {
				continue
			}
			seen[name] = true
			cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format:  "SELECT {*} FROM files WHERE file_path = {filePath} OR file_path LIKE {pattern} ESCAPE '\\' ORDER BY file_path",
				Values: []any{
					sq.Param("filePath", path.Join(sitePrefix, parent, name)),
					sq.Param("pattern", wildcardReplacer.Replace(path.Join(sitePrefix, parent, name))+"/%"),
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
				fileType, ok := fileTypes[path.Ext(file.FilePath)]
				if !ok {
					continue
				}
				fmt.Printf("dumping: %s\n", file.FilePath)
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
				} else {
					tarHeader.Typeflag = tar.TypeReg
					tarHeader.Mode = 0644
				}
				tarWriter.WriteHeader(tarHeader)
				if fileType.IsObject {
					reader, err := databaseFS.ObjectStorage.Get(ctx, file.FileID.String()+path.Ext(file.FilePath))
					if err != nil {
						reader.Close()
						cleanup(err)
						return
					}
					_, err = io.Copy(tarWriter, reader)
					if err != nil {
						reader.Close()
						cleanup(err)
						return
					}
					err = reader.Close()
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
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
		}
	}
}
