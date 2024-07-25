package nb10

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"runtime/debug"
	"strings"
	"sync/atomic"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) calculatestorage(w http.ResponseWriter, r *http.Request, user User) {
	if nbrew.DB == nil {
		nbrew.NotFound(w, r)
		return
	}
	if r.Method != "POST" {
		nbrew.MethodNotAllowed(w, r)
		return
	}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType == "multipart/form-data" {
		err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
		if err != nil {
			nbrew.BadRequest(w, r, err)
			return
		}
	} else {
		err := r.ParseForm()
		if err != nil {
			nbrew.BadRequest(w, r, err)
			return
		}
	}
	group, groupctx := errgroup.WithContext(r.Context())
	siteNames := r.Form["siteName"]
	for _, siteName := range siteNames {
		siteName := siteName
		group.Go(func() (err error) {
			defer func() {
				if v := recover(); v != nil {
					err = fmt.Errorf("panic: " + string(debug.Stack()))
				}
			}()
			exists, err := sq.FetchExists(groupctx, nbrew.DB, sq.Query{
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
			var root string
			if siteName == "" {
				root = "."
			} else if strings.Contains(siteName, ".") {
				root = siteName
			} else {
				root = "@" + siteName
			}
			storageUsed, err := calculateStorageUsed(r.Context(), nbrew.FS, root)
			if err != nil {
				return err
			}
			_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
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
	err := group.Wait()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	err = nbrew.SetFlashSession(w, r, map[string]any{
		"postRedirectGet": map[string]any{
			"from": "calculatestorage",
		},
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	referer := r.Referer()
	if referer == "" {
		http.Redirect(w, r, "/files/", http.StatusFound)
		return
	}
	http.Redirect(w, r, referer, http.StatusFound)
}

func calculateStorageUsed(ctx context.Context, fsys FS, root string) (int64, error) {
	if databaseFS, ok := fsys.(*DatabaseFS); ok {
		var filter sq.Expression
		if root == "." {
			filter = sq.Expr("(" +
				"files.file_path LIKE 'notes/%' ESCAPE '\\'" +
				" OR files.file_path LIKE 'pages/%' ESCAPE '\\'" +
				" OR files.file_path LIKE 'posts/%' ESCAPE '\\'" +
				" OR files.file_path LIKE 'output/%' ESCAPE '\\'" +
				" OR files.file_path LIKE 'imports/%' ESCAPE '\\'" +
				" OR files.file_path LIKE 'exports/%' ESCAPE '\\'" +
				" OR files.file_path = 'site.json'" +
				")")
		} else {
			filter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(root)+"/%")
		}
		storageUsed, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE {filter}",
			Values: []any{
				sq.Param("filter", filter),
			},
		}, func(row *sq.Row) int64 {
			return row.Int64("sum(coalesce(size, 0))")
		})
		if err != nil {
			return 0, err
		}
		return storageUsed, nil
	}
	var storageUsed atomic.Int64
	walkDirFunc := func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if dirEntry.IsDir() {
			return nil
		}
		fileInfo, err := dirEntry.Info()
		if err != nil {
			return err
		}
		storageUsed.Add(fileInfo.Size())
		return nil
	}
	if root == "." {
		group, groupctx := errgroup.WithContext(ctx)
		for _, root := range []string{"notes", "pages", "posts", "output", "imports", "exports", "site.json"} {
			root := root
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				err = fs.WalkDir(fsys.WithContext(groupctx), root, walkDirFunc)
				if err != nil {
					return err
				}
				return nil
			})
		}
		err := group.Wait()
		if err != nil {
			return 0, err
		}
	} else {
		err := fs.WalkDir(fsys.WithContext(ctx), root, walkDirFunc)
		if err != nil {
			return 0, err
		}
	}
	return storageUsed.Load(), nil
}
