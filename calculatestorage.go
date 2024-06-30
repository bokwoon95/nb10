package nb10

import (
	"encoding/json"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/bokwoon95/nb10/sq"
)

func (nbrew *Notebrew) calculatestorage(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Response struct {
		SitePrefix  string `json:"sitePrefix"`
		StorageUsed int64  `json:"storageUsed"`
	}
	if nbrew.DB == nil {
		nbrew.notFound(w, r)
		return
	}
	databaseFS, ok := nbrew.FS.(*DatabaseFS)
	if !ok {
		nbrew.notFound(w, r)
		return
	}
	response := Response{
		SitePrefix: sitePrefix,
	}
	var parentFilter sq.Expression
	if sitePrefix == "" {
		parentFilter = sq.Expr("(" +
			"files.file_path LIKE 'notes/%'" +
			" OR files.file_path LIKE 'pages/%'" +
			" OR files.file_path LIKE 'posts/%'" +
			" OR files.file_path LIKE 'output/%'" +
			" OR files.file_path LIKE 'imports/%'" +
			" OR files.file_path LIKE 'exports/%'" +
			" OR files.file_path = 'site.json'" +
			")")
	} else {
		parentFilter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(sitePrefix)+"/%")
	}
	storageUsed, err := sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
		Dialect: databaseFS.Dialect,
		Format:  "SELECT {*} FROM files WHERE {parentFilter}",
		Values: []any{
			sq.Param("parentFilter", parentFilter),
		},
	}, func(row *sq.Row) int64 {
		return row.Int64("sum(coalesce(size, 0))")
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	response.StorageUsed = storageUsed
	_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
		Dialect: nbrew.Dialect,
		Format:  "UPDATE site SET storage_used = {storageUsed} WHERE site_name = {siteName}",
		Values: []any{
			sq.Int64Param("storageUsed", storageUsed),
			sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
		},
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	switch r.Method {
	case "GET":
		if r.Form.Has("api") {
			w.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(w)
			encoder.SetIndent("", "  ")
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(&response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
			}
			return
		}
		w.Write([]byte(strconv.FormatInt(storageUsed, 10)))
	case "POST":
		if r.Form.Has("api") {
			w.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(w)
			encoder.SetIndent("", "  ")
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(&response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
			}
			return
		}
		referer := r.Referer()
		if referer == "" {
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
			return
		}
		http.Redirect(w, r, referer, http.StatusFound)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
