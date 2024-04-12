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
	names := r.Form["name"]
	if len(names) == 0 {
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(w)
		defer gzipWriter.Close()
		defer func() {
			gzipWriter.Reset(io.Discard)
			gzipWriterPool.Put(gzipWriter)
		}()
		tarWriter := tar.NewWriter(gzipWriter)
		defer tarWriter.Close()
	}
}
