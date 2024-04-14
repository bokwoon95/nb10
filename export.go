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
)

func (nbrew *Notebrew) export(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	// parent=xxxx&name=xxxx&name=xxxx
	if r.Method != "GET" && r.Method != "HEAD" {
		nbrew.methodNotAllowed(w, r)
		return
	}
	parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
	if parent == "." {
		if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
			_ = databaseFS
			if sitePrefix == "" {
				return
			}
		} else {
		}
		return
	}
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
	names := r.Form["name"]
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(w)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()
	if len(names) == 0 {
		var fileName string
		if sitePrefix == "" {
			fileName = "files-" + time.Now().UTC().Format("20060102150405") + ".tgz"
		} else {
			fileName = "files-" + strings.TrimPrefix(sitePrefix, "@") + "-" + time.Now().UTC().Format("20060102150405") + ".tgz"
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fileName+`"`)
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
