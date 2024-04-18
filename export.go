package nb10

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) export(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type DatabaseFile struct {
		FileID       ID
		FilePath     string
		IsDir        bool
		ModTime      time.Time
		CreationTime time.Time
		Bytes        []byte
	}
	type File struct {
		FileID       ID        `json:"fileID"`
		FilePath     string    `json:"filePath"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		Size         int64     `json:"size"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Bytes        []byte    `json:"-"`
	}
	type Request struct {
		Parent string   `json:"parent"`
		Names  []string `json:"names"`
	}
	type Response struct {
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
		response.Files = make([]File, len(names))
		for i, name := range names {
			i, name := i, filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			group.Go(func() error {
				if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
					_ = databaseFS
				}
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
		}, func(row *sq.Row) DatabaseFile {
			b = row.Bytes(b[:0], "COALESCE(text, data)")
			file := DatabaseFile{
				FileID:   row.UUID("file_id"),
				FilePath: row.String("file_path"),
				IsDir:    row.Bool("is_dir"),
				Bytes:    b,
			}
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
