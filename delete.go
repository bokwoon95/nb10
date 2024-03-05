package nb10

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) delete(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		Parent string   `json:"parent"`
		Names  []string `json:"names"`
	}
	type File struct {
		Name    string    `json:"name"`
		IsDir   bool      `json:"isDir"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"modTime"`
	}
	type Response struct {
		Error        string     `json:"status"`
		DeleteErrors []string   `json:"deleteErrors"`
		ContentSite  string     `json:"contentSite"`
		Username     NullString `json:"username"`
		SitePrefix   string     `json:"sitePrefix"`
		Parent       string     `json:"parent"`
		Files        []File     `json:"files"`
	}

	isValidParent := func(parent string) bool {
		head, _, _ := strings.Cut(parent, "/")
		switch head {
		case "notes", "pages", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, parent))
			if err != nil {
				return false
			}
			if fileInfo.IsDir() {
				return true
			}
		}
		return false
	}

	switch r.Method {
	case "GET":
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
			referer := getReferer(r)
			funcMap := map[string]any{
				"join":       path.Join,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"stylesCSS":  func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS": func() template.JS { return template.JS(baselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("delete.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/delete.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
			executeTemplate(w, r, tmpl, &response)
		}

		var response Response
		_, err := nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentSite = nbrew.contentSite(sitePrefix)
		response.Username = NullString{String: user.Username, Valid: nbrew.DB != nil}
		response.SitePrefix = sitePrefix
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		if !isValidParent(response.Parent) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		seen := make(map[string]bool)
		group, groupctx := errgroup.WithContext(r.Context())
		names := r.Form["name"]
		response.Files = make([]File, len(names))
		for i, name := range names {
			i, name := i, filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			group.Go(func() error {
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctx), path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				response.Files[i] = File{
					Name:    fileInfo.Name(),
					IsDir:   fileInfo.IsDir(),
					Size:    fileInfo.Size(),
					ModTime: fileInfo.ModTime(),
				}
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		n := 0
		for _, file := range response.Files {
			if file.Name == "" {
				continue
			}
			response.Files[n] = file
			n++
		}
		response.Files = response.Files[:n]
		writeResponse(w, r, response)
	case "POST":
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
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "delete")+"/?parent="+url.QueryEscape(response.Parent), http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":       "delete",
					"numDeleted": len(response.Files),
					"numErrors":  len(response.DeleteErrors),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			head, tail, _ := strings.Cut(response.Parent, "/")
			if head != "output" {
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
				return
			}
			next, _, _ := strings.Cut(tail, "/")
			switch next {
			case "themes":
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
				return
			case "posts":
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, tail+".md"), http.StatusFound)
				return
			case "":
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "pages/index.html"), http.StatusFound)
				return
			default:
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "pages", tail+".html"), http.StatusFound)
				return
			}
		}

		var request Request
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
				if err != nil {
					badRequest(w, r, err)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					badRequest(w, r, err)
					return
				}
			}
			request.Parent = r.Form.Get("parent")
			request.Names = r.Form["name"]
		default:
			unsupportedContentType(w, r)
			return
		}

		var response Response
		response.Parent = path.Clean(strings.Trim(request.Parent, "/"))
		if !isValidParent(response.Parent) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		seen := make(map[string]bool)
		n := 0
		for _, name := range request.Names {
			name := filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			request.Names[n] = name
			n++
		}
		request.Names = request.Names[:n]
		slices.Sort(request.Names)

		type deleteAction struct {
			deleteFiles       bool
			deleteDirectories bool
		}
		outputDirsToDelete := make(map[string]deleteAction)
		outputDirsToDeleteMu := sync.Mutex{}
		_ = outputDirsToDelete
		outputDirsToDeleteMu.Lock()
		outputDirsToDeleteMu.Unlock()
		var (
			restoreIndexHTML           = false
			restore404HTML             = false
			restorePostHTML            = false
			restorePostListHTML        = false
			regenerateIndexHTML        = false
			regenerate404HTML          = false
			regenerateCategoryPosts    = sql.NullString{}
			regenerateCategoryPostList = sql.NullString{}
			regenerateParentPage       = sql.NullString{} // "pages/foo/bar/baz.html"
			regenerateParentPost       = sql.NullString{} // "posts/foo/bar/baz.md"
		)
		var (
			_ = restoreIndexHTML
			_ = restore404HTML
			_ = restorePostHTML
			_ = restorePostListHTML
			_ = regenerateIndexHTML
			_ = regenerate404HTML
			_ = regenerateCategoryPosts
			_ = regenerateCategoryPostList
			_ = regenerateParentPage
			_ = regenerateParentPost
		)
		// 1. delete files
		// 2. delete outputDir (if an entire post category was deleted, we also delete the entire output/posts/{category})
		// 3. if index.html | 404.html was deleted, fill them in with embed/index.html | embed/404.html and regenerate the pages
		// 4. if post.html was deleted, fill it in with embed/post.html and regenerate all posts for the category
		// 5. if (postlist.html was deleted or a post was deleted), if (postlist.html was deleted) fill it in with embed/postlist.html. then, regenerate the postlist for the category
		// 6. if a page was deleted, regenerate the parent page
		// 7. if a page asset or page image was deleted, regenerate the page
		// 8. if a post image was deleted, regenerate the post

		// TODO: we can gate the siteGen creation behind all the booleans
		// defined above so that if there's no need to regenerate anything we
		// can skip the database call that NewSiteGenerator() makes.
		siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}

		head, tail, _ := strings.Cut(response.Parent, "/")
		response.DeleteErrors = make([]string, len(request.Names))
		response.Files = make([]File, len(request.Names))
		switch head {
		case "notes":
			group, groupctx := errgroup.WithContext(r.Context())
			for i, name := range request.Names {
				i, name := i, name
				group.Go(func() error {
					err := nbrew.FS.WithContext(groupctx).RemoveAll(path.Join(sitePrefix, response.Parent, name))
					if err != nil {
						response.DeleteErrors[i] = err.Error()
						return nil
					}
					response.Files[i] = File{Name: name}
					return nil
				})
			}
			err := group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		case "pages":
			for i := 0; i < len(request.Names); i++ {
				// nameA := request.Names[i]
				// fileInfoA, err := fs.Stat(path.Join(sitePrefix, response.Parent, nameA))
				// if err != nil {
				// 	getLogger(r.Context()).Error(err.Error())
				// 	internalServerError(w, r, err)
				// 	return
				// }
				// var nameB string
				// var fileInfoB fs.FileInfo
				// if i+1 < len(request.Names) {
				// 	nameB = request.Names[i+1]
				// }
				// if nameB != "" {
				// 	fileInfoB, err = fs.Stat(path.Join(sitePrefix, response.Parent, nameB))
				// 	if err != nil {
				// 		getLogger(r.Context()).Error(err.Error())
				// 		internalServerError(w, r, err)
				// 		return
				// 	}
				// }
			}
		case "posts":
			group, groupctx := errgroup.WithContext(r.Context())
			for i, name := range request.Names {
				i, name := i, name
				group.Go(func() error {
					err := nbrew.FS.WithContext(groupctx).RemoveAll(path.Join(sitePrefix, response.Parent, name))
					if err != nil {
						response.DeleteErrors[i] = err.Error()
						return nil
					}
					response.Files[i] = File{Name: name}
					if !strings.HasSuffix(name, ".md") {
						return nil
					}
					err = nbrew.FS.WithContext(groupctx).RemoveAll(path.Join(sitePrefix, "output", response.Parent, strings.TrimSuffix(name, ".md")))
					if err != nil {
						getLogger(groupctx).Error(err.Error())
						return nil
					}
					return nil
				})
			}
			err := group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		case "output":
		}

		// output/foo/bar/ files | dirs | both
		// NOTE!! This requires knowing whether foo.html is indeed a file, and whether foo is indeed a folder. So we still need to cache the FileInfo of some sort. Maybe a custom looping construct where we evaluate the next two items at once and advance the counter one more time if both items belong to a pair (e.g. foo and foo.html).
		// It is not enough to know that foo and foo.html exist, we must confirm that foo is a folder and foo.html is a file.
		// Since we evaluate up to two items at once, within the same loop we can delete the outputDir since we can determine if two items belonging to a pair exist (or not).
		// Then within this loop we can also regenerate accordingly...?

		// map that keeps track of which outputDirs we have to delete
		// - the map value need to indicate whether it was the file or folder that was deleted, or both
		// map that keeps track of which pages or posts or post list needs to be regenerated.
		// deleting a page or post should first involve deleting the source file (and replacing it if it is a permanent file), deleting the contents of the outputDir, then regenerating the parent page if head is pages, regenerating the post list if head is posts.
		group, groupctx := errgroup.WithContext(r.Context())
		pageFiles := make(map[string]struct{})
		pageDirs := make(map[string]struct{})
		for i, name := range request.Names {
			i, name := i, filepath.ToSlash(name)
			if strings.Contains(name, "/") {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			group.Go(func() error {
				filePath := path.Join(sitePrefix, response.Parent, name)
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctx), filePath)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					response.DeleteErrors[i] = err.Error()
					return nil
				}
				_ = fileInfo
				err = nbrew.FS.WithContext(groupctx).RemoveAll(filePath)
				if err != nil {
					response.DeleteErrors[i] = err.Error()
					return nil
				}
				response.Files[i] = File{Name: name}
				switch head {
				case "pages":
					if tail == "" && (name == "index.html" || name == "404.html") {
						b, err := fs.ReadFile(RuntimeFS, path.Join("embed", name))
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages", name), 0644)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						defer writer.Close()
						_, err = writer.Write(b)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						err = writer.Close()
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						err = siteGen.GeneratePage(groupctx, path.Join("pages", name), string(b))
						if err != nil {
							var templateErr TemplateError
							if !errors.As(err, &templateErr) {
								getLogger(groupctx).Error(err.Error())
								return nil
							}
						}
					}
					if fileInfo.IsDir() {
						outputDir := path.Join(sitePrefix, "output", tail, name)
						pageDirs[outputDir] = struct{}{}
					} else {
						outputDir := path.Join(sitePrefix, "output", tail, strings.TrimSuffix(name, path.Ext(name)))
						pageFiles[outputDir] = struct{}{}
					}
				case "posts":
					err := nbrew.FS.WithContext(groupctx).RemoveAll(path.Join(sitePrefix, "output", response.Parent, strings.TrimSuffix(name, path.Ext(name))))
					if err != nil {
						getLogger(groupctx).Error(err.Error())
						return nil
					}
					if strings.HasSuffix(name, ".md") {
						siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						category := tail
						tmpl, err := siteGen.PostListTemplate(r.Context(), category)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						_, err = siteGen.GeneratePostList(r.Context(), category, tmpl)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
					}
				case "output":
					if tail != "themes" {
						return nil
					}
					switch name {
					case "post.html":
						file, err := RuntimeFS.Open("embed/post.html")
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						defer file.Close()
						writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "output/themes/post.html"), 0644)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						defer writer.Close()
						_, err = io.Copy(writer, file)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						err = writer.Close()
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
					case "postlist.html":
						file, err := RuntimeFS.Open("embed/postlist.html")
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						defer file.Close()
						writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "output/themes/postlist.html"), 0644)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						defer writer.Close()
						_, err = io.Copy(writer, file)
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
						err = writer.Close()
						if err != nil {
							getLogger(groupctx).Error(err.Error())
							return nil
						}
					}
				}
				return nil
			})
		}
		if "" != "" {
			// TODO: regenerate the post list template if head is posts
			category := tail
			tmpl, err := siteGen.PostListTemplate(r.Context(), category)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			_, err = siteGen.GeneratePostList(r.Context(), category, tmpl)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}

		}
		// NOTE: if we deleted even a single post we must regenerate the post list. If we deleted even a single page we must regenerate the parent page.
		if head == "output" {
			next, _, _ := strings.Cut(tail, "/")
			if next == "posts" {
				// TODO: regenerate the post list
			}
		}
		n = 0
		for _, file := range response.Files {
			if file.Name == "" {
				continue
			}
			response.Files[n] = file
			n++
		}
		response.Files = response.Files[:n]
		n = 0
		for _, errmsg := range response.DeleteErrors {
			if errmsg == "" {
				continue
			}
			response.DeleteErrors[n] = errmsg
			n++
		}
		response.DeleteErrors = response.DeleteErrors[:n]
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
