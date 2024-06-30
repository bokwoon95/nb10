package nb10

import (
	"mime"
	"net/http"
	"strings"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) calculatestorage(w http.ResponseWriter, r *http.Request, user User) {
	if nbrew.DB == nil {
		nbrew.notFound(w, r)
		return
	}
	databaseFS, ok := nbrew.FS.(*DatabaseFS)
	if !ok {
		nbrew.notFound(w, r)
		return
	}
	if r.Method != "POST" {
		nbrew.methodNotAllowed(w, r)
		return
	}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType == "multipart/form-data" {
		err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
		if err != nil {
			nbrew.badRequest(w, r, err)
			return
		}
	} else {
		err := r.ParseForm()
		if err != nil {
			nbrew.badRequest(w, r, err)
			return
		}
	}
	group, groupctx := errgroup.WithContext(r.Context())
	siteNames := r.Form["siteName"]
	for _, siteName := range siteNames {
		siteName := siteName
		group.Go(func() error {
			exists, err := sq.FetchExists(groupctx, nbrew.DB, sq.Query{
				Debug:   true,
				Dialect: nbrew.Dialect,
				Format: "SELECT 1" +
					" FROM site_owner" +
					" WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName})" +
					" AND user_id = (SELECT user_id FROM users WHERE username = {username})",
				Values: []any{
					sq.StringParam("siteName", siteName),
					sq.StringParam("username", user.Username),
				},
			})
			if err != nil {
				return err
			}
			if !exists {
				return nil
			}
			var parentFilter sq.Expression
			if siteName == "" {
				parentFilter = sq.Expr("(" +
					"files.file_path LIKE 'notes/%'" +
					" OR files.file_path LIKE 'pages/%'" +
					" OR files.file_path LIKE 'posts/%'" +
					" OR files.file_path LIKE 'output/%'" +
					" OR files.file_path LIKE 'imports/%'" +
					" OR files.file_path LIKE 'exports/%'" +
					" OR files.file_path = 'site.json'" +
					")")
			} else if strings.Contains(siteName, ".") {
				parentFilter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(siteName)+"/%")
			} else {
				parentFilter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace("@"+siteName)+"/%")
			}
			storageUsed, err := sq.FetchOne(r.Context(), databaseFS.DB, sq.Query{
				Debug:   true,
				Dialect: databaseFS.Dialect,
				Format:  "SELECT {*} FROM files WHERE {parentFilter}",
				Values: []any{
					sq.Param("parentFilter", parentFilter),
				},
			}, func(row *sq.Row) int64 {
				return row.Int64("sum(coalesce(size, 0))")
			})
			if err != nil {
				return err
			}
			_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Debug:   true,
				Dialect: nbrew.Dialect,
				Format:  "UPDATE site SET storage_used = {storageUsed} WHERE site_name = {siteName}",
				Values: []any{
					sq.Int64Param("storageUsed", storageUsed),
					sq.StringParam("siteName", siteName),
				},
			})
			if err != nil {
				return err
			}
			return nil
		})
	}
	referer := r.Referer()
	if referer == "" {
		http.Redirect(w, r, "/files/", http.StatusFound)
		return
	}
	http.Redirect(w, r, referer, http.StatusFound)
}
