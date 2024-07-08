package nb10

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

var errInvalid = fmt.Errorf("src file is invalid or is a directory containing files that are invalid")

func (nbrew *Notebrew) clipboard(w http.ResponseWriter, r *http.Request, user User, sitePrefix, action string) {
	if r.Method != "POST" {
		nbrew.MethodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
	err := r.ParseForm()
	if err != nil {
		nbrew.BadRequest(w, r, err)
		return
	}
	referer := r.Referer()
	if referer == "" {
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
		return
	}
	switch action {
	case "cut", "copy":
		parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		head, _, _ := strings.Cut(parent, "/")
		switch head {
		case "notes", "pages", "posts", "output", "exports":
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, parent))
			if err != nil || !fileInfo.IsDir() {
				http.Redirect(w, r, referer, http.StatusFound)
				return
			}
		default:
			http.Redirect(w, r, referer, http.StatusFound)
			return
		}
		names := r.Form["name"]
		if len(names) == 0 {
			http.Redirect(w, r, referer, http.StatusFound)
			return
		}
		clipboard := make(url.Values)
		if action == "cut" {
			clipboard.Set("cut", "")
		}
		clipboard.Set("sitePrefix", sitePrefix)
		clipboard.Set("parent", parent)
		clipboard["name"] = names
		http.SetCookie(w, &http.Cookie{
			Path:     "/" + path.Join("files", sitePrefix) + "/",
			Name:     "clipboard",
			Value:    clipboard.Encode(),
			MaxAge:   int(time.Hour.Seconds()),
			Secure:   r.TLS != nil,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, referer, http.StatusFound)
	case "clear":
		http.SetCookie(w, &http.Cookie{
			Path:     "/" + path.Join("files", sitePrefix) + "/",
			Name:     "clipboard",
			Value:    "0",
			MaxAge:   -1,
			Secure:   r.TLS != nil,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, referer, http.StatusFound)
	case "paste":
		type Response struct {
			Error             string            `json:"error"`
			IsCut             bool              `json:"isCut"`
			SrcParent         string            `json:"srcParent"`
			DestParent        string            `json:"destParent"`
			FilesNotExist     []string          `json:"filesNotExist"`
			FilesExist        []string          `json:"filesExist"`
			FilesInvalid      []string          `json:"filesInvalid"`
			FilesPasted       []string          `json:"filesPasted"`
			RegenerationStats RegenerationStats `json:"regenerationStats"`
		}
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if response.Error == "" {
				if len(response.FilesExist) > 0 || len(response.FilesInvalid) > 0 {
					clipboard := make(url.Values)
					if action == "cut" {
						clipboard.Set("cut", "")
					}
					clipboard.Set("parent", response.SrcParent)
					clipboard["name"] = append(clipboard["name"], response.FilesExist...)
					clipboard["name"] = append(clipboard["name"], response.FilesInvalid...)
					http.SetCookie(w, &http.Cookie{
						Path:     "/" + path.Join("files", sitePrefix) + "/",
						Name:     "clipboard",
						Value:    clipboard.Encode(),
						MaxAge:   int(time.Hour.Seconds()),
						Secure:   r.TLS != nil,
						HttpOnly: true,
						SameSite: http.SameSiteLaxMode,
					})
				} else {
					http.SetCookie(w, &http.Cookie{
						Path:     "/" + path.Join("files", sitePrefix) + "/",
						Name:     "clipboard",
						Value:    "0",
						MaxAge:   -1,
						Secure:   r.TLS != nil,
						HttpOnly: true,
						SameSite: http.SameSiteLaxMode,
					})
				}
			}
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			if response.Error != "" {
				err := nbrew.SetSession(w, r, "flash", map[string]any{
					"postRedirectGet": map[string]any{
						"from":  "clipboard/paste",
						"error": response.Error,
					},
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, referer, http.StatusFound)
				return
			}
			err := nbrew.SetSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":          "clipboard/paste",
					"srcParent":     response.SrcParent,
					"destParent":    response.DestParent,
					"isCut":         response.IsCut,
					"filesNotExist": response.FilesNotExist,
					"filesExist":    response.FilesExist,
					"filesInvalid":  response.FilesInvalid,
					"filesPasted":   response.FilesPasted,
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, referer, http.StatusFound)
		}
		response := Response{
			FilesNotExist: []string{},
			FilesExist:    []string{},
			FilesInvalid:  []string{},
			FilesPasted:   []string{},
		}
		cookie, _ := r.Cookie("clipboard")
		if cookie == nil {
			response.Error = "CookieNotProvided"
			writeResponse(w, r, response)
			return
		}
		clipboard, err := url.ParseQuery(cookie.Value)
		if err != nil {
			response.Error = "InvalidCookieValue"
			writeResponse(w, r, response)
			return
		}
		if clipboard.Get("sitePrefix") != sitePrefix {
			response.Error = "SitePrefixNotMatch"
			writeResponse(w, r, response)
			return
		}
		response.IsCut = clipboard.Has("cut")
		names := clipboard["name"]
		slices.Sort(names)
		names = slices.Compact(names)
		var storageRemaining *atomic.Int64
		if nbrew.DB != nil {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT 1" +
					" FROM site" +
					" JOIN site_user ON site_user.site_id = site.site_id" +
					" JOIN users ON users.user_id = site_user.user_id" +
					" WHERE site.site_name = {siteName}" +
					" AND users.username = {username}",
				Values: []any{
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
					sq.StringParam("username", user.Username),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			if !exists {
				nbrew.NotAuthorized(w, r)
				return
			}
			_, isDatabaseFS := nbrew.FS.(*DatabaseFS)
			if isDatabaseFS && user.StorageLimit >= 0 {
				storageUsed, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format: "SELECT {*}" +
						" FROM site" +
						" JOIN site_owner ON site_owner.site_id = site.site_id" +
						" WHERE site_owner.user_id = {userID}",
					Values: []any{
						sq.UUIDParam("userID", user.UserID),
					},
				}, func(row *sq.Row) int64 {
					return row.Int64("sum(CASE WHEN site.storage_used IS NOT NULL AND site.storage_used > 0 THEN site.storage_used ELSE 0 END)")
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				storageRemaining = &atomic.Int64{}
				storageRemaining.Store(user.StorageLimit - storageUsed)
			}
		}
		response.SrcParent = path.Clean(strings.Trim(clipboard.Get("parent"), "/"))
		srcHead, srcTail, _ := strings.Cut(response.SrcParent, "/")
		switch srcHead {
		case "notes", "pages", "posts", "output", "exports":
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, response.SrcParent))
			if err != nil || !fileInfo.IsDir() {
				response.Error = "InvalidSrcParent"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidSrcParent"
			writeResponse(w, r, response)
			return
		}
		response.DestParent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		destHead, destTail, _ := strings.Cut(response.DestParent, "/")
		switch destHead {
		case "notes", "pages", "posts", "output", "imports":
			fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, response.DestParent))
			if err != nil || !fileInfo.IsDir() {
				response.Error = "InvalidDestParent"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidDestParent"
			writeResponse(w, r, response)
			return
		}
		if response.SrcParent == response.DestParent {
			response.Error = "PasteSameDestination"
			writeResponse(w, r, response)
			return
		}
		for _, name := range names {
			if strings.HasPrefix(response.DestParent, path.Join(response.SrcParent, name)+"/") {
				response.Error = "PasteIntoSelf"
				writeResponse(w, r, response)
				return
			}
		}
		if destHead == "posts" {
			if srcHead != "posts" {
				response.Error = "PostNoPaste"
				writeResponse(w, r, response)
				return
			}
			if !response.IsCut {
				response.Error = "PostNoCopy"
				writeResponse(w, r, response)
				return
			}
		}
		var waitGroup sync.WaitGroup
		waitGroup.Add(4)
		notExistCh := make(chan string)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					fmt.Println("panic:\n" + string(debug.Stack()))
				}
			}()
			defer waitGroup.Done()
			for name := range notExistCh {
				response.FilesNotExist = append(response.FilesNotExist, name)
			}
		}()
		existCh := make(chan string)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					fmt.Println("panic:\n" + string(debug.Stack()))
				}
			}()
			defer waitGroup.Done()
			for name := range existCh {
				response.FilesExist = append(response.FilesExist, name)
			}
		}()
		invalidCh := make(chan string)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					fmt.Println("panic:\n" + string(debug.Stack()))
				}
			}()
			defer waitGroup.Done()
			for name := range invalidCh {
				response.FilesInvalid = append(response.FilesInvalid, name)
			}
		}()
		pastedCh := make(chan string)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					fmt.Println("panic:\n" + string(debug.Stack()))
				}
			}()
			defer waitGroup.Done()
			for name := range pastedCh {
				response.FilesPasted = append(response.FilesPasted, name)
			}
		}()
		moveNotAllowed := (srcHead == "pages" && destHead != "pages") || (srcHead == "posts" && destHead != "posts")
		group, groupctx := errgroup.WithContext(r.Context())
		for _, name := range names {
			name := name
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				srcFilePath := path.Join(sitePrefix, response.SrcParent, name)
				srcFileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctx), srcFilePath)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						notExistCh <- name
						return nil
					}
					return err
				}
				destFilePath := path.Join(sitePrefix, response.DestParent, name)
				_, err = fs.Stat(nbrew.FS.WithContext(groupctx), destFilePath)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return err
					}
				} else {
					existCh <- name
					return nil
				}
				switch destHead {
				case "pages":
					if !srcFileInfo.IsDir() {
						if !strings.HasSuffix(srcFilePath, ".html") {
							invalidCh <- name
							return nil
						}
					} else {
						if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
							exists, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
								Dialect: databaseFS.Dialect,
								Format:  "SELECT 1 FROM files WHERE file_path LIKE {pattern} AND NOT is_dir AND file_path NOT LIKE '%.html'",
								Values: []any{
									sq.StringParam("pattern", wildcardReplacer.Replace(srcFilePath)+"/%"),
								},
							})
							if err != nil {
								return err
							}
							if exists {
								invalidCh <- name
								return nil
							}
						} else {
							err := fs.WalkDir(nbrew.FS.WithContext(groupctx), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
								if err != nil {
									return err
								}
								if !dirEntry.IsDir() && !strings.HasSuffix(filePath, ".html") {
									return errInvalid
								}
								return nil
							})
							if err != nil {
								if errors.Is(err, errInvalid) {
									invalidCh <- name
									return nil
								}
								return err
							}
						}
					}
				case "posts":
					if !srcFileInfo.IsDir() {
						if !strings.HasSuffix(srcFilePath, ".md") {
							invalidCh <- name
							return nil
						}
					} else {
						if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
							exists, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
								Dialect: databaseFS.Dialect,
								Format:  "SELECT 1 FROM files WHERE file_path LIKE {pattern} AND NOT is_dir AND file_path NOT LIKE '%.md'",
								Values: []any{
									sq.StringParam("pattern", wildcardReplacer.Replace(srcFilePath)+"/%"),
								},
							})
							if err != nil {
								return err
							}
							if exists {
								invalidCh <- name
								return nil
							}
						} else {
							err := fs.WalkDir(nbrew.FS.WithContext(groupctx), srcFilePath, func(filePath string, dirEntry fs.DirEntry, err error) error {
								if err != nil {
									return err
								}
								if !dirEntry.IsDir() && !strings.HasSuffix(filePath, ".md") {
									return errInvalid
								}
								return nil
							})
							if err != nil {
								if errors.Is(err, errInvalid) {
									invalidCh <- name
									return nil
								}
								return err
							}
						}
					}
				case "output":
					next, _, _ := strings.Cut(destTail, "/")
					if next != "themes" {
						if srcFileInfo.IsDir() {
							invalidCh <- name
							return nil
						}
						ext := path.Ext(srcFilePath)
						if next == "posts" {
							switch ext {
							case ".jpeg", ".jpg", ".png", ".webp", ".gif":
								break
							default:
								invalidCh <- name
								return nil
							}
						} else {
							switch ext {
							case ".jpeg", ".jpg", ".png", ".webp", ".gif", ".css", ".js", ".md":
								break
							default:
								invalidCh <- name
								return nil
							}
						}
					}
				case "imports":
					if !srcFileInfo.IsDir() {
						if !strings.HasSuffix(srcFilePath, ".tgz") {
							invalidCh <- name
							return nil
						}
					} else {
						invalidCh <- name
						return nil
					}
				}
				pastedCh <- name
				isPermanentFile := false
				if !srcFileInfo.IsDir() {
					switch response.SrcParent {
					case "pages":
						isPermanentFile = name == "index.html" || name == "404.html"
					case "output/themes":
						isPermanentFile = name == "post.html" || name == "postlist.html" || name == "postlist.json"
					}
				}
				isMove := response.IsCut && !moveNotAllowed && !isPermanentFile
				if isMove {
					err := nbrew.FS.WithContext(groupctx).Rename(srcFilePath, destFilePath)
					if err != nil {
						return err
					}
				} else {
					if storageRemaining != nil {
						storageUsed, err := calculateStorageUsed(groupctx, nbrew.FS, srcFilePath)
						if err != nil {
							return err
						}
						if storageRemaining.Add(-storageUsed) <= 0 {
							return ErrStorageLimitExceeded
						}
					}
					err := nbrew.FS.WithContext(groupctx).Copy(srcFilePath, destFilePath)
					if err != nil {
						return err
					}
				}
				if srcHead == "posts" && destHead == "posts" {
					// example: posts/foobar.md (must be a file) and posts/foobar (must
					// be a dir) are counterparts that share the same output directory
					// (output/posts/foobar).
					var counterpart, srcOutputDir, destOutputDir string
					if !srcFileInfo.IsDir() {
						counterpart = strings.TrimSuffix(srcFilePath, ".md")
						srcOutputDir = path.Join(sitePrefix, "output/posts", srcTail, strings.TrimSuffix(name, ".md"))
						destOutputDir = path.Join(sitePrefix, "output/posts", destTail, strings.TrimSuffix(name, ".md"))
					} else {
						counterpart = srcFilePath + ".md"
						srcOutputDir = path.Join(sitePrefix, "output/posts", srcTail, name)
						destOutputDir = path.Join(sitePrefix, "output/posts", destTail, name)
					}
					var counterpartExists bool
					counterpartFileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), counterpart)
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							return err
						}
					} else {
						counterpartExists = counterpartFileInfo.IsDir() != srcFileInfo.IsDir()
					}
					if !counterpartExists {
						// Fast path: if the counterpart doesn't exist, we can
						// just rename the entire output directory.
						err := nbrew.FS.WithContext(groupctx).Rename(srcOutputDir, destOutputDir)
						if err != nil {
							return err
						}
					} else {
						// Otherwise, we have to loop over each corresponding
						// item in the output directory one by one to rename
						// it.
						err := nbrew.FS.WithContext(groupctx).MkdirAll(destOutputDir, 0755)
						if err != nil {
							return err
						}
						dirEntries, err := nbrew.FS.WithContext(groupctx).ReadDir(srcOutputDir)
						if err != nil {
							return err
						}
						subgroup, subctx := errgroup.WithContext(groupctx)
						for _, dirEntry := range dirEntries {
							if dirEntry.IsDir() == srcFileInfo.IsDir() {
								name := dirEntry.Name()
								subgroup.Go(func() (err error) {
									defer func() {
										if v := recover(); v != nil {
											err = fmt.Errorf("panic: " + string(debug.Stack()))
										}
									}()
									return nbrew.FS.WithContext(subctx).Rename(path.Join(srcOutputDir, name), path.Join(destOutputDir, name))
								})
							}
						}
						err = subgroup.Wait()
						if err != nil {
							return err
						}
					}
				} else if srcHead == "pages" && destHead == "pages" {
					// example: pages/foobar.html (must be a file) and pages/foobar
					// (must be a dir) are counterparts that share the same output
					// directory (output/foobar).
					var counterpart, srcOutputDir, destOutputDir string
					if !srcFileInfo.IsDir() {
						counterpart = strings.TrimSuffix(srcFilePath, ".html")
						srcOutputDir = path.Join(sitePrefix, "output", srcTail, strings.TrimSuffix(name, ".html"))
						destOutputDir = path.Join(sitePrefix, "output", destTail, strings.TrimSuffix(name, ".html"))
					} else {
						counterpart = srcFilePath + ".html"
						srcOutputDir = path.Join(sitePrefix, "output", srcTail, name)
						destOutputDir = path.Join(sitePrefix, "output", destTail, name)
					}
					var counterpartExists bool
					counterpartFileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), counterpart)
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							return err
						}
					} else {
						counterpartExists = counterpartFileInfo.IsDir() != srcFileInfo.IsDir()
					}
					if !counterpartExists {
						// Fast path: if the counterpart doesn't exist, we can
						// just rename or copy the entire output directory.
						if isMove {
							err = nbrew.FS.WithContext(groupctx).Rename(srcOutputDir, destOutputDir)
							if err != nil {
								return err
							}
						} else {
							if storageRemaining != nil {
								storageUsed, err := calculateStorageUsed(groupctx, nbrew.FS, srcFilePath)
								if err != nil {
									return err
								}
								if storageRemaining.Add(-storageUsed) <= 0 {
									return ErrStorageLimitExceeded
								}
							}
							err = nbrew.FS.WithContext(groupctx).Copy(srcOutputDir, destOutputDir)
							if err != nil {
								return err
							}
						}
					} else {
						// Otherwise, we have to loop over each corresponding
						// item in the output directory one by one to rename or
						// copy it.
						err := nbrew.FS.WithContext(groupctx).MkdirAll(destOutputDir, 0755)
						if err != nil {
							return err
						}
						dirEntries, err := nbrew.FS.WithContext(groupctx).ReadDir(srcOutputDir)
						if err != nil {
							return err
						}
						subgroup, subctx := errgroup.WithContext(groupctx)
						for _, dirEntry := range dirEntries {
							if dirEntry.IsDir() == srcFileInfo.IsDir() {
								name := dirEntry.Name()
								subgroup.Go(func() (err error) {
									defer func() {
										if v := recover(); v != nil {
											err = fmt.Errorf("panic: " + string(debug.Stack()))
										}
									}()
									if isMove {
										return nbrew.FS.WithContext(subctx).Rename(path.Join(srcOutputDir, name), path.Join(destOutputDir, name))
									} else {
										if storageRemaining != nil {
											storageUsed, err := calculateStorageUsed(groupctx, nbrew.FS, path.Join(srcOutputDir, name))
											if err != nil {
												return err
											}
											if storageRemaining.Add(-storageUsed) <= 0 {
												return ErrStorageLimitExceeded
											}
										}
										return nbrew.FS.WithContext(subctx).Copy(path.Join(srcOutputDir, name), path.Join(destOutputDir, name))
									}
								})
							}
						}
						err = subgroup.Wait()
						if err != nil {
							return err
						}
					}
				}
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			if errors.Is(err, ErrStorageLimitExceeded) {
				nbrew.StorageLimitExceeded(w, r)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		close(notExistCh)
		close(existCh)
		close(invalidCh)
		close(pastedCh)
		if srcHead == "posts" && destHead == "posts" {
			func() {
				siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
					FS:                 nbrew.FS,
					ContentDomain:      nbrew.ContentDomain,
					ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
					ImgDomain:          nbrew.ImgDomain,
					SitePrefix:         sitePrefix,
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					return
				}
				srcCategory := srcTail
				srcTemplate, err := siteGen.PostListTemplate(r.Context(), srcCategory)
				if err != nil {
					if !errors.As(err, &response.RegenerationStats.TemplateError) {
						getLogger(r.Context()).Error(err.Error())
					}
					return
				}
				_, err = siteGen.GeneratePostList(r.Context(), srcCategory, srcTemplate)
				if err != nil {
					if !errors.As(err, &response.RegenerationStats.TemplateError) {
						getLogger(r.Context()).Error(err.Error())
					}
					return
				}
				destCategory := destTail
				destTemplate, err := siteGen.PostListTemplate(r.Context(), destCategory)
				if err != nil {
					if !errors.As(err, &response.RegenerationStats.TemplateError) {
						getLogger(r.Context()).Error(err.Error())
					}
					return
				}
				_, err = siteGen.GeneratePostList(r.Context(), destCategory, destTemplate)
				if err != nil {
					if !errors.As(err, &response.RegenerationStats.TemplateError) {
						getLogger(r.Context()).Error(err.Error())
					}
					return
				}
			}()
		}
		waitGroup.Wait()
		writeResponse(w, r, response)
	default:
		nbrew.NotFound(w, r)
	}
}
