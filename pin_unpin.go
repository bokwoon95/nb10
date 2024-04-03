package nb10

import (
	"errors"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) pin(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Response struct {
		Error     string `json:"error"`
		Parent    string `json:"parent"`
		NumPinned int    `json:"numPinned"`
	}
	if r.Method != "POST" {
		nbrew.methodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
	err := r.ParseForm()
	if err != nil {
		nbrew.badRequest(w, r, err)
		return
	}
	referer := r.Referer()
	if referer == "" {
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
		return
	}
	parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
	head, _, _ := strings.Cut(parent, "/")
	switch head {
	case "notes", "pages", "posts", "output":
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, parent))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// TODO: return InvalidParent as error.
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		if !fileInfo.IsDir() {
			http.Redirect(w, r, referer, http.StatusFound)
			return
		}
	}
	names := r.Form["name"]
	if len(names) == 0 {
		http.Redirect(w, r, referer, http.StatusFound)
		return
	}
	slices.Sort(names)
	names = slices.Compact(names)
	response := Response{}
	numPinned := atomic.Int64{}
	_ = &numPinned
	var preparedExec *sq.PreparedExec
	switch nbrew.Dialect {
	case "sqlite", "postgres":
		preparedExec, err = sq.PrepareExec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO pinned_file (parent_id, file_id)" +
				" VALUES ((SELECT file_id FROM files WHERE file_path = {parent}), (SELECT file_id FROM files WHERE file_path = {filePath}))" +
				" ON CONFLICT DO NOTHING",
			Values: []any{
				sq.StringParam("parent", path.Join(sitePrefix, parent)),
				sq.StringParam("filePath", ""),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
	case "mysql":
		preparedExec, err = sq.PrepareExec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO pinned_file (parent_id, file_id)" +
				" VALUES ((SELECT file_id FROM files WHERE file_path = {parent}), (SELECT file_id FROM files WHERE file_path = {filePath}))" +
				" ON DUPLICATE KEY UPDATE parent_id = parent_id",
			Values: []any{
				sq.StringParam("parent", path.Join(sitePrefix, parent)),
				sq.StringParam("filePath", ""),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
	default:
		response.Error = "unspported dialect"
	}
	group, groupctx := errgroup.WithContext(r.Context())
	for _, name := range names {
		name := name
		group.Go(func() error {
			// TODO: we need to vet each
			preparedExec.Exec(groupctx, sq.StringParam("filePath", path.Join(sitePrefix, name)))
			return nil
		})
	}
	_ = response
}

func (nbrew *Notebrew) unpin(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
}
