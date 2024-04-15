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
	// parent=xxxx&name=xxxx&name=xxxx
	type DatabaseFile struct {
		FileID   ID
		FilePath string
		IsDir    bool
		Bytes    []byte
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		nbrew.methodNotAllowed(w, r)
		return
	}
	parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
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
	gzipReader := gzipReaderPool.Get().(*gzip.Reader)
	defer func() {
		gzipReader.Reset(empty)
		gzipReaderPool.Put(gzipReader)
	}()
	b := bufPool.Get().(*bytes.Buffer).Bytes()
	defer func() {
		if cap(b) <= maxPoolableBufferCapacity {
			b = b[:0]
			bufPool.Put(bytes.NewBuffer(b))
		}
	}()
	if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
		var parentFilter sq.Expression
		if parent == "." {
			parentFilter = sq.Expr("(file_path LIKE 'notes/%'" +
				" OR file_path LIKE 'pages/%'" +
				" OR file_path LIKE 'posts/%'" +
				" OR file_path LIKE 'output/%'" +
				" OR parent_id IS NULL)")
		} else {
			parentFilter = sq.Expr("file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(sitePrefix)+"/%")
		}
		sq.FetchCursor(r.Context(), databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE {parentFilter} ORDER BY file_path",
			Values: []any{
				sq.Param("parentFilter", parentFilter),
			},
		}, func(row *sq.Row) DatabaseFile {
			file := DatabaseFile{
				FileID:   row.UUID("file_id"),
				FilePath: row.String("file_path"),
				IsDir:    row.Bool("is_dir"),
				Bytes:    row.Bytes(b[:0], "COALESCE(text, data)"),
			}
			if sitePrefix != "" {
				file.FilePath = strings.TrimPrefix(strings.TrimPrefix(file.FilePath, sitePrefix), "/")
			}
			return file
		})
		// TODO: if we want to avoid the N+1 problems arising from calling
		// fs.WalkDir, we'll need to walk the rows ourselves and uncompress
		// gzippable files and fetching objects from ObjectStorage
		// https://boehs.org/node/llms-destroying-internetaccordingly.
	} else {
	}
	names := r.Form["name"]
	if len(names) == 0 {
		if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
			_ = databaseFS
		} else {
			subFS, err := fs.Sub(nbrew.FS.WithContext(r.Context()), parent)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			err = tarWriter.AddFS(subFS)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				return
			}
			err = tarWriter.Close()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				return
			}
			err = gzipWriter.Close()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				return
			}
			return
		}
	}
}
