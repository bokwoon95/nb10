package nb10

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) regenerate(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	type Response struct {
		Count         int           `json:"count"`
		TimeTaken     string        `json:"timeTaken"`
		TemplateError TemplateError `json:"templateError"`
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
		err := nbrew.setSession(w, r, "flash", map[string]any{
			"postRedirectGet": map[string]any{
				"from":          "regenerate",
				"count":         response.Count,
				"timeTaken":     response.TimeTaken,
				"templateError": response.TemplateError,
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, referer, http.StatusFound)
	}
	if r.Method != "POST" {
		methodNotAllowed(w, r)
		return
	}
	result, err := nbrew.RegenerateSite(r.Context(), sitePrefix)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	response := Response{
		Count:         result.Count,
		TimeTaken:     result.TimeTaken.String(),
		TemplateError: result.TemplateError,
	}
	writeResponse(w, r, response)
}

type RegenerateSiteResult struct {
	Count         int
	TimeTaken     time.Duration
	TemplateError TemplateError
}

func (nbrew *Notebrew) RegenerateSite(ctx context.Context, sitePrefix string) (RegenerateSiteResult, error) {
	siteGen, err := NewSiteGenerator(ctx, nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
	if err != nil {
		return RegenerateSiteResult{}, err
	}
	pagesDir := path.Join(sitePrefix, "pages")
	postsDir := path.Join(sitePrefix, "posts")
	postTemplate, err := siteGen.PostTemplate(ctx, "")
	if err != nil {
		return RegenerateSiteResult{}, err
	}
	postTemplates := map[string]*template.Template{
		"": postTemplate,
	}
	postListTemplate, err := siteGen.PostListTemplate(ctx, "")
	if err != nil {
		return RegenerateSiteResult{}, err
	}
	postListTemplates := map[string]*template.Template{
		"": postListTemplate,
	}
	var result RegenerateSiteResult
	var count atomic.Int64
	startedAt := time.Now()

	if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
		type File struct {
			FilePath     string
			Text         string
			CreationTime time.Time
		}
		group, groupctx := errgroup.WithContext(ctx)
		group.Go(func() error {
			cursor, err := sq.FetchCursor(groupctx, remoteFS.DB, sq.Query{
				Dialect: remoteFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE file_path LIKE {pattern} ESCAPE '\\'" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.html'",
				Values: []any{
					sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(pagesDir)+"/%"),
				},
			}, func(row *sq.Row) File {
				return File{
					FilePath: row.String("file_path"),
					Text:     row.String("text"),
				}
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			subgroup, subctx := errgroup.WithContext(groupctx)
			for cursor.Next() {
				file, err := cursor.Result()
				if err != nil {
					return err
				}
				subgroup.Go(func() error {
					if sitePrefix != "" {
						_, file.FilePath, _ = strings.Cut(file.FilePath, "/")
					}
					err := siteGen.GeneratePage(subctx, file.FilePath, file.Text)
					if err != nil {
						return err
					}
					count.Add(1)
					return nil
				})
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		group.Go(func() error {
			cursorA, err := sq.FetchCursor(groupctx, remoteFS.DB, sq.Query{
				Dialect: remoteFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {postsDir})" +
					" AND is_dir",
				Values: []any{
					sq.StringParam("postsDir", postsDir),
				},
			}, func(row *sq.Row) string {
				return row.String("file_path")
			})
			if err != nil {
				return err
			}
			defer cursorA.Close()
			var mutex sync.Mutex
			subgroupA, subctxA := errgroup.WithContext(groupctx)
			for cursorA.Next() {
				filePath, err := cursorA.Result()
				if err != nil {
					return err
				}
				subgroupA.Go(func() error {
					category := path.Base(filePath)
					postTemplate, err := siteGen.PostTemplate(subctxA, category)
					if err != nil {
						return err
					}
					postListTemplate, err := siteGen.PostListTemplate(subctxA, category)
					if err != nil {
						return err
					}
					mutex.Lock()
					postTemplates[category] = postTemplate
					postListTemplates[category] = postListTemplate
					mutex.Unlock()
					return nil
				})
			}
			err = cursorA.Close()
			if err != nil {
				return err
			}
			err = subgroupA.Wait()
			if err != nil {
				return err
			}
			cursorB, err := sq.FetchCursor(groupctx, remoteFS.DB, sq.Query{
				Dialect: remoteFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE file_path LIKE {pattern} ESCAPE '\\'" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.md'",
				Values: []any{
					sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(postsDir)+"/%"),
				},
			}, func(row *sq.Row) File {
				return File{
					FilePath:     row.String("file_path"),
					Text:         row.String("text"),
					CreationTime: row.Time("creation_time"),
				}
			})
			if err != nil {
				return err
			}
			defer cursorB.Close()
			subgroupB, subctxB := errgroup.WithContext(groupctx)
			for cursorB.Next() {
				file, err := cursorB.Result()
				if err != nil {
					return err
				}
				subgroupB.Go(func() error {
					if sitePrefix != "" {
						_, file.FilePath, _ = strings.Cut(file.FilePath, "/")
					}
					_, category, _ := strings.Cut(path.Dir(file.FilePath), "/")
					if category == "." {
						category = ""
					}
					postTemplate := postTemplates[category]
					if postTemplate == nil {
						return nil
					}
					err = siteGen.GeneratePost(subctxB, file.FilePath, file.Text, file.CreationTime, postTemplate)
					if err != nil {
						return err
					}
					count.Add(1)
					return nil
				})
			}
			err = cursorB.Close()
			if err != nil {
				return err
			}
			for category, postListTemplate := range postListTemplates {
				category, postListTemplate := category, postListTemplate
				subgroupB.Go(func() error {
					n, err := siteGen.GeneratePostList(subctxB, category, postListTemplate)
					if err != nil {
						return err
					}
					count.Add(int64(n))
					return nil
				})
			}
			err = subgroupB.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		err = group.Wait()
		if err != nil {
			if !errors.As(err, &result.TemplateError) {
				return RegenerateSiteResult{}, nil
			}
		}
		result.Count = int(count.Load())
		result.TimeTaken = time.Since(startedAt)
		return result, nil
	}

	group, groupctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		subgroup, subctx := errgroup.WithContext(groupctx)
		err := fs.WalkDir(nbrew.FS.WithContext(groupctx), pagesDir, func(filePath string, dirEntry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if filePath == pagesDir {
				return nil
			}
			subgroup.Go(func() error {
				file, err := nbrew.FS.WithContext(subctx).Open(filePath)
				if err != nil {
					return err
				}
				fileInfo, err := file.Stat()
				if err != nil {
					return err
				}
				if fileInfo.IsDir() || !strings.HasSuffix(filePath, ".html") {
					return nil
				}
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return err
				}
				if sitePrefix != "" {
					_, filePath, _ = strings.Cut(filePath, "/")
				}
				err = siteGen.GeneratePage(subctx, filePath, b.String())
				if err != nil {
					return err
				}
				count.Add(1)
				return nil
			})
			return nil
		})
		err = subgroup.Wait()
		if err != nil {
			return err
		}
		if err != nil {
			return err
		}
		return nil
	})
	group.Go(func() error {
		dirEntries, err := nbrew.FS.WithContext(groupctx).ReadDir(postsDir)
		if err != nil {
			return err
		}
		var mutex sync.Mutex
		subgroupA, subctxA := errgroup.WithContext(groupctx)
		for _, dirEntry := range dirEntries {
			if !dirEntry.IsDir() {
				continue
			}
			category := dirEntry.Name()
			subgroupA.Go(func() error {
				postTemplate, err := siteGen.PostTemplate(subctxA, category)
				if err != nil {
					return err
				}
				postListTemplate, err := siteGen.PostListTemplate(subctxA, category)
				if err != nil {
					return err
				}
				mutex.Lock()
				postTemplates[category] = postTemplate
				postListTemplates[category] = postListTemplate
				mutex.Unlock()
				return nil
			})
		}
		err = subgroupA.Wait()
		if err != nil {
			return err
		}
		subgroupB, subctxB := errgroup.WithContext(groupctx)
		err = fs.WalkDir(nbrew.FS.WithContext(groupctx), postsDir, func(filePath string, dirEntry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if sitePrefix != "" {
				_, filePath, _ = strings.Cut(filePath, "/")
			}
			if dirEntry.IsDir() {
				_, category, _ := strings.Cut(filePath, "/")
				if strings.Contains(category, "/") {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(filePath, ".md") {
				return nil
			}
			subgroupB.Go(func() error {
				_, category, _ := strings.Cut(path.Dir(filePath), "/")
				if category == "." {
					category = ""
				}
				postTemplate := postTemplates[category]
				if postTemplate == nil {
					return nil
				}
				file, err := nbrew.FS.WithContext(subctxB).Open(path.Join(sitePrefix, filePath))
				if err != nil {
					return err
				}
				defer file.Close()
				fileInfo, err := file.Stat()
				if err != nil {
					return err
				}
				var b strings.Builder
				b.Grow(int(fileInfo.Size()))
				_, err = io.Copy(&b, file)
				if err != nil {
					return err
				}
				var absolutePath string
				if localFS, ok := nbrew.FS.(*LocalFS); ok {
					absolutePath = path.Join(localFS.RootDir, sitePrefix, filePath)
				}
				creationTime := CreationTime(absolutePath, fileInfo)
				err = siteGen.GeneratePost(subctxB, filePath, b.String(), creationTime, postTemplate)
				if err != nil {
					return err
				}
				count.Add(1)
				return nil
			})
			return nil
		})
		for category, postListTemplate := range postListTemplates {
			category, postListTemplate := category, postListTemplate
			subgroupB.Go(func() error {
				n, err := siteGen.GeneratePostList(subctxB, category, postListTemplate)
				if err != nil {
					return err
				}
				count.Add(int64(n))
				return nil
			})
		}
		err = subgroupB.Wait()
		if err != nil {
			return err
		}
		return nil
	})
	err = group.Wait()
	if err != nil {
		if !errors.As(err, &result.TemplateError) {
			return RegenerateSiteResult{}, err
		}
	}
	result.Count = int(count.Load())
	result.TimeTaken = time.Since(startedAt)
	return result, nil
}
