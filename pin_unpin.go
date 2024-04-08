package nb10

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"time"

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
	databaseFS, ok := nbrew.FS.(*DatabaseFS)
	if !ok {
		nbrew.notFound(w, r)
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
		if response.Error != "" {
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
			return
		}
		err := nbrew.setSession(w, r, "flash", map[string]any{
			"postRedirectGet": map[string]any{
				"from":      "pin",
				"numPinned": response.NumPinned,
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, referer, http.StatusFound)
	}
	response := Response{
		Parent: path.Clean(strings.Trim(r.Form.Get("parent"), "/")),
	}
	head, _, _ := strings.Cut(response.Parent, "/")
	if head != "notes" && head != "pages" && head != "posts" && head != "output" {
		response.Error = "InvalidParent"
		writeResponse(w, r, response)
		return
	}
	parentID, err := sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
		Dialect: databaseFS.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {parent} AND is_dir",
		Values: []any{
			sq.StringParam("parent", path.Join(sitePrefix, response.Parent)),
		},
	}, func(row *sq.Row) ID {
		return row.UUID("file_id")
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	names := r.Form["name"]
	if len(names) == 0 {
		http.Redirect(w, r, referer, http.StatusFound)
		return
	}
	slices.Sort(names)
	names = slices.Compact(names)
	numPinned := atomic.Int64{}
	creationTime := time.Now()
	var preparedExec *sq.PreparedExec
	defer func() {
		if preparedExec == nil {
			return
		}
		preparedExec.Close()
	}()
	switch nbrew.Dialect {
	case "sqlite", "postgres":
		preparedExec, err = sq.PrepareExec(r.Context(), databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "INSERT INTO pinned_file (parent_id, file_id, creation_time)" +
				" SELECT {parentID}, file_id, {creationTime} FROM files WHERE file_path = {filePath}" +
				" ON CONFLICT DO NOTHING",
			Values: []any{
				sq.UUIDParam("parentID", parentID),
				sq.TimeParam("creationTime", creationTime),
				sq.StringParam("filePath", ""),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
	case "mysql":
		preparedExec, err = sq.PrepareExec(r.Context(), databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "INSERT INTO pinned_file (parent_id, file_id, creation_time)" +
				" SELECT {parentID}, file_id, {creationTime} FROM files WHERE file_path = {filePath}" +
				" ON DUPLICATE KEY UPDATE parent_id = parent_id",
			Values: []any{
				sq.UUIDParam("parentID", parentID),
				sq.TimeParam("creationTime", creationTime),
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
		if strings.Contains(name, "/") {
			continue
		}
		group.Go(func() error {
			result, err := preparedExec.Exec(groupctx, sq.StringParam("filePath", path.Join(sitePrefix, response.Parent, name)))
			if err != nil {
				return err
			}
			if result.RowsAffected > 0 {
				numPinned.Add(1)
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
	response.NumPinned = int(numPinned.Load())
	writeResponse(w, r, response)
}

func (nbrew *Notebrew) unpin(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Response struct {
		Error       string `json:"error"`
		Parent      string `json:"parent"`
		NumUnpinned int    `json:"numUnpinned"`
	}
	if r.Method != "POST" {
		nbrew.methodNotAllowed(w, r)
		return
	}
	databaseFS, ok := nbrew.FS.(*DatabaseFS)
	if !ok {
		nbrew.notFound(w, r)
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
		if response.Error != "" {
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
			return
		}
		err := nbrew.setSession(w, r, "flash", map[string]any{
			"postRedirectGet": map[string]any{
				"from":        "unpin",
				"numUnpinned": response.NumUnpinned,
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, referer, http.StatusFound)
	}
	response := Response{
		Parent: path.Clean(strings.Trim(r.Form.Get("parent"), "/")),
	}
	head, _, _ := strings.Cut(response.Parent, "/")
	if head != "notes" && head != "pages" && head != "posts" && head != "output" {
		response.Error = "InvalidParent"
		writeResponse(w, r, response)
		return
	}
	parentID, err := sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
		Dialect: databaseFS.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {parent} AND is_dir",
		Values: []any{
			sq.StringParam("parent", path.Join(sitePrefix, response.Parent)),
		},
	}, func(row *sq.Row) ID {
		return row.UUID("file_id")
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	names := r.Form["name"]
	if len(names) == 0 {
		http.Redirect(w, r, referer, http.StatusFound)
		return
	}
	slices.Sort(names)
	names = slices.Compact(names)
	numUnpinned := atomic.Int64{}
	preparedExec, err := sq.PrepareExec(r.Context(), databaseFS.DB, sq.Query{
		Dialect: databaseFS.Dialect,
		Format: "DELETE FROM pinned_file" +
			" WHERE parent_id = {parentID}" +
			" AND file_id = (SELECT file_id FROM files WHERE file_path = {filePath})",
		Values: []any{
			sq.UUIDParam("parentID", parentID),
			sq.StringParam("filePath", ""),
		},
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	defer preparedExec.Close()
	group, groupctx := errgroup.WithContext(r.Context())
	for _, name := range names {
		name := name
		if strings.Contains(name, "/") {
			continue
		}
		group.Go(func() error {
			result, err := preparedExec.Exec(groupctx, sq.StringParam("filePath", path.Join(sitePrefix, response.Parent, name)))
			if err != nil {
				return err
			}
			if result.RowsAffected > 0 {
				numUnpinned.Add(1)
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
	response.NumUnpinned = int(numUnpinned.Load())
	writeResponse(w, r, response)
}