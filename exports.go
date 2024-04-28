package nb10

import (
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

func (nbrew *Notebrew) exports(w http.ResponseWriter, r *http.Request, user User, sitePrefix, tgzFileName string) {
	if tgzFileName != "" {
		if r.Method != "GET" {
			nbrew.methodNotAllowed(w, r)
			return
		}
		if strings.Contains(tgzFileName, "/") || !strings.HasSuffix(tgzFileName, ".tgz") {
			nbrew.notFound(w, r)
			return
		}
		file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(sitePrefix, "exports", tgzFileName))
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
		serveFile(w, r, file, fileInfo, fileTypes[".tgz"], "no-store, max-age=0")
		return
	}
}
