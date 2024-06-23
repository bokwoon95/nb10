package nb10

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

var errInvalid = fmt.Errorf("src file is invalid or is a directory containing files that are invalid")

func (nbrew *Notebrew) clipboard(w http.ResponseWriter, r *http.Request, user User, sitePrefix, action string) {
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
			Error             string            `json:"error,omitempty"`
			IsCut             bool              `json:"isCut,omitempty"`
			SrcParent         string            `json:"srcParent,omitempty"`
			DestParent        string            `json:"destParent,omitempty"`
			FilesNotExist     []string          `json:"filesNotExist,omitempty"`
			FilesExist        []string          `json:"filesExist,omitempty"`
			FilesInvalid      []string          `json:"filesInvalid,omitempty"`
			FilesPasted       []string          `json:"filesPasted,omitmepty"`
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
			if response.Error != "" {
				err := nbrew.setSession(w, r, "flash", map[string]any{
					"postRedirectGet": map[string]any{
						"from":  "clipboard/paste",
						"error": response.Error,
					},
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, referer, http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
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
				nbrew.internalServerError(w, r, err)
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
				nbrew.internalServerError(w, r, err)
				return
			}
			if !exists {
				nbrew.notAuthorized(w, r)
				return
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
		case "notes", "pages", "posts", "output", "exports":
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
			defer waitGroup.Done()
			for name := range notExistCh {
				response.FilesNotExist = append(response.FilesNotExist, name)
			}
		}()
		existCh := make(chan string)
		go func() {
			defer waitGroup.Done()
			for name := range existCh {
				response.FilesExist = append(response.FilesExist, name)
			}
		}()
		invalidCh := make(chan string)
		go func() {
			defer waitGroup.Done()
			for name := range invalidCh {
				response.FilesInvalid = append(response.FilesInvalid, name)
			}
		}()
		pastedCh := make(chan string)
		go func() {
			defer waitGroup.Done()
			for name := range pastedCh {
				response.FilesPasted = append(response.FilesPasted, name)
			}
		}()
		moveNotAllowed := (srcHead == "pages" && destHead != "pages") || (srcHead == "posts" && destHead != "posts")
		group, groupctx := errgroup.WithContext(r.Context())
		for _, name := range names {
			name := name
			group.Go(func() error {
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
				}
				pastedCh <- name
				isPermanentFile := false
				if !srcFileInfo.IsDir() {
					switch response.SrcParent {
					case "pages":
						isPermanentFile = name == "index.html" || name == "404.html"
					case "output/themes":
						isPermanentFile = name == "post.html" || name == "postlist.html"
					}
				}
				isMove := response.IsCut && !moveNotAllowed && !isPermanentFile
				if isMove {
					err := nbrew.FS.WithContext(groupctx).Rename(srcFilePath, destFilePath)
					if err != nil {
						return err
					}
				} else {
					err := nbrew.FS.WithContext(groupctx).Copy(srcFilePath, destFilePath)
					if err != nil {
						return err
					}
				}
				if !(srcHead == "pages" && destHead == "pages") && !(srcHead == "posts" && destHead == "posts") {
					return nil
				}
				if srcHead == "posts" && destHead == "posts" {
					// TODO: also apply the counterpart logic here.
					if !isMove {
						panic("unreachable: PostNoCopy")
					}
					var srcOutputDir, destOutputDir string
					if !srcFileInfo.IsDir() {
						srcOutputDir = path.Join(sitePrefix, "output/posts", srcTail, strings.TrimSuffix(name, ".md"))
						destOutputDir = path.Join(sitePrefix, "output/posts", destTail, strings.TrimSuffix(name, ".md"))
					} else {
						srcOutputDir = path.Join(sitePrefix, "output/posts", srcTail, name)
						destOutputDir = path.Join(sitePrefix, "output/posts", destTail, name)
					}
					err = nbrew.FS.WithContext(groupctx).Rename(srcOutputDir, destOutputDir)
					if err != nil {
						return err
					}
					return nil
				}
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
					counterpartExists = true
				}
				if !counterpartExists || counterpartFileInfo.IsDir() == srcFileInfo.IsDir() {
					if isMove {
						err = nbrew.FS.WithContext(groupctx).Rename(srcOutputDir, destOutputDir)
						if err != nil {
							return err
						}
					} else {
						err = nbrew.FS.WithContext(groupctx).Copy(srcOutputDir, destOutputDir)
						if err != nil {
							return err
						}
					}
					return nil
				}
				err = nbrew.FS.WithContext(groupctx).MkdirAll(destOutputDir, 0755)
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
						subgroup.Go(func() error {
							if isMove {
								return nbrew.FS.WithContext(subctx).Rename(path.Join(srcOutputDir, name), path.Join(destOutputDir, name))
							} else {
								return nbrew.FS.WithContext(subctx).Copy(path.Join(srcOutputDir, name), path.Join(destOutputDir, name))
							}
						})
					}
				}
				err = subgroup.Wait()
				if err != nil {
					return err
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
		nbrew.notFound(w, r)
	}
}
