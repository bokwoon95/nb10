package nb10

import (
	"archive/tar"
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
	if parent == "." {
		if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
			_ = databaseFS
			var parentFilter sq.Expression
			_ = parentFilter
			if parent == "." {
				parentFilter = sq.Expr("(files.file_path LIKE 'notes/%'" +
					" OR files.file_path LIKE 'pages/%'" +
					" OR files.file_path LIKE 'posts/%'" +
					" OR files.file_path LIKE 'output/%'" +
					" OR files.parent_id IS NULL)")
			} else {
				parentFilter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(sitePrefix)+"/%")
			}
		} else {
		}
		return
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
