package nb10

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/nb10/sq"
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
	if r.Method != "GET" && r.Method != "HEAD" {
		nbrew.methodNotAllowed(w, r)
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
	// TODO: check for a "confirm" query param and initiate download only if it exists. Else, default to showing the user a confirmation page.
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
