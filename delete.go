package nb10

import (
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
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) delete(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type File struct {
		FileID  ID        `json:"fileID"`
		Name    string    `json:"name"`
		IsDir   bool      `json:"isDir"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"modTime"`
	}
	type Request struct {
		Parent string   `json:"parent"`
		Names  []string `json:"names"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		ImgDomain         string            `json:"imgDomain"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		Parent            string            `json:"parent"`
		Files             []File            `json:"files"`
		Error             string            `json:"error"`
		DeleteErrors      []string          `json:"deleteErrors"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
	}

	isValidParent := func(parent string) bool {
		head, _, _ := strings.Cut(parent, "/")
		switch head {
		case "notes", "pages", "posts", "output":
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
				"ext":        path.Ext,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("delete.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/delete.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.executeTemplate(w, r, tmpl, &response)
		}

		var response Response
		_, err := nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentBaseURL = nbrew.contentBaseURL(sitePrefix)
		response.ImgDomain = nbrew.ImgDomain
		_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
		response.UserID = user.UserID
		response.Username = user.Username
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
				file := File{
					Name:    fileInfo.Name(),
					IsDir:   fileInfo.IsDir(),
					Size:    fileInfo.Size(),
					ModTime: fileInfo.ModTime(),
				}
				if fileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
					file.FileID = fileInfo.FileID
				}
				response.Files[i] = file
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
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
					nbrew.internalServerError(w, r, err)
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
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
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
				nbrew.badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
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
			request.Parent = r.Form.Get("parent")
			request.Names = r.Form["name"]
		default:
			nbrew.unsupportedContentType(w, r)
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
		var (
			outputDirsToDelete          = make(map[string]deleteAction)
			outputDirsToDeleteMutex     = sync.Mutex{}
			resetIndexHTML              atomic.Bool
			reset404HTML                atomic.Bool
			restoreCategoryPostHTML     atomic.Pointer[string]
			restoreCategoryPostListHTML atomic.Pointer[string]
			regenerateCategoryPosts     atomic.Pointer[string]
			regenerateCategoryPostList  atomic.Pointer[string]
			regenerateParentPage        atomic.Pointer[string]
			regenerateParentPost        atomic.Pointer[string]
		)
		head, tail, _ := strings.Cut(response.Parent, "/")
		groupA, groupctxA := errgroup.WithContext(r.Context())
		response.DeleteErrors = make([]string, len(request.Names))
		response.Files = make([]File, len(request.Names))
		for i, name := range request.Names {
			i, name := i, name
			groupA.Go(func() error {
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctxA), path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				if head == "posts" && name == "postlist.json" {
					return nil
				}
				err = nbrew.FS.WithContext(groupctxA).RemoveAll(path.Join(sitePrefix, response.Parent, name))
				if err != nil {
					response.DeleteErrors[i] = err.Error()
					return nil
				}
				response.Files[i] = File{Name: name}
				switch head {
				case "pages":
					if fileInfo.IsDir() {
						outputDir := path.Join("output", tail, name)
						outputDirsToDeleteMutex.Lock()
						deleteAction := outputDirsToDelete[outputDir]
						deleteAction.deleteDirectories = true
						outputDirsToDelete[outputDir] = deleteAction
						outputDirsToDeleteMutex.Unlock()
					} else {
						if tail == "" {
							if name == "index.html" {
								outputDir := "output"
								outputDirsToDeleteMutex.Lock()
								deleteAction := outputDirsToDelete[outputDir]
								deleteAction.deleteFiles = true
								outputDirsToDelete[outputDir] = deleteAction
								outputDirsToDeleteMutex.Unlock()
								resetIndexHTML.Store(true)
							} else {
								outputDir := path.Join("output", strings.TrimSuffix(name, ".html"))
								outputDirsToDeleteMutex.Lock()
								deleteAction := outputDirsToDelete[outputDir]
								deleteAction.deleteFiles = true
								outputDirsToDelete[outputDir] = deleteAction
								outputDirsToDeleteMutex.Unlock()
								if name == "404.html" {
									reset404HTML.Store(true)
								} else {
									parentPage := "pages/index.html"
									regenerateParentPage.Store(&parentPage)
								}
							}
						} else {
							outputDir := path.Join("output", tail, strings.TrimSuffix(name, ".html"))
							outputDirsToDeleteMutex.Lock()
							deleteAction := outputDirsToDelete[outputDir]
							deleteAction.deleteFiles = true
							outputDirsToDelete[outputDir] = deleteAction
							outputDirsToDeleteMutex.Unlock()
							parentPage := response.Parent + ".html"
							regenerateParentPage.Store(&parentPage)
						}
					}
				case "posts":
					category := path.Dir(tail)
					if category == "." {
						category = ""
					}
					if !strings.Contains(category, "/") {
						if strings.HasSuffix(name, ".md") {
							outputDir := path.Join("output/posts", tail, strings.TrimSuffix(name, ".md"))
							outputDirsToDeleteMutex.Lock()
							deleteAction := outputDirsToDelete[outputDir]
							deleteAction.deleteFiles = true
							deleteAction.deleteDirectories = true
							outputDirsToDelete[outputDir] = deleteAction
							outputDirsToDeleteMutex.Unlock()
							regenerateCategoryPostList.Store(&category)
						} else if name == "post.html" {
							restoreCategoryPostHTML.Store(&category)
							regenerateCategoryPosts.Store(&category)
						} else if name == "postlist.html" {
							restoreCategoryPostListHTML.Store(&category)
							regenerateCategoryPostList.Store(&category)
						}
					}
				case "output":
					if !fileInfo.IsDir() {
						next, _, _ := strings.Cut(tail, "/")
						if next == "posts" {
							switch path.Ext(name) {
							case ".jpeg", ".jpg", ".png", ".webp", ".gif":
								parentPost := tail + ".md"
								regenerateParentPost.Store(&parentPost)
							}
						} else if next != "themes" {
							switch path.Ext(name) {
							case ".jpeg", ".jpg", ".png", ".webp", ".gif", ".md":
								var parentPage string
								if tail == "" {
									parentPage = "pages/index.html"
								} else {
									parentPage = path.Join("pages", tail+".html")
								}
								regenerateParentPage.Store(&parentPage)
							}
						}
					}
				}
				return nil
			})
		}
		err := groupA.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}

		groupB, groupctxB := errgroup.WithContext(r.Context())
		for outputDir, deleteAction := range outputDirsToDelete {
			outputDir, deleteAction := outputDir, deleteAction
			groupB.Go(func() error {
				if deleteAction.deleteFiles && deleteAction.deleteDirectories {
					return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
				}
				_, tail, _ := strings.Cut(outputDir, "/")
				if deleteAction.deleteFiles {
					if tail != "" {
						fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctxB), path.Join("pages", tail))
						if err != nil {
							if errors.Is(err, fs.ErrNotExist) {
								return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
							} else {
								return err
							}
						} else {
							if !fileInfo.IsDir() {
								return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
							}
						}
					}
					dirEntries, err := nbrew.FS.WithContext(groupctxB).ReadDir(path.Join(sitePrefix, outputDir))
					if err != nil {
						return err
					}
					subgroup, subctx := errgroup.WithContext(groupctxB)
					for _, dirEntry := range dirEntries {
						if dirEntry.IsDir() {
							continue
						}
						name := dirEntry.Name()
						subgroup.Go(func() error {
							return nbrew.FS.WithContext(subctx).RemoveAll(path.Join(sitePrefix, outputDir, name))
						})
					}
					return subgroup.Wait()
				}
				if deleteAction.deleteDirectories {
					if tail != "" {
						fileInfo, err := fs.Stat(nbrew.FS.WithContext(groupctxB), path.Join("pages", tail+".html"))
						if err != nil {
							if errors.Is(err, fs.ErrNotExist) {
								return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
							} else {
								return err
							}
						} else {
							if fileInfo.IsDir() {
								return nbrew.FS.WithContext(groupctxB).RemoveAll(path.Join(sitePrefix, outputDir))
							}
						}
					}
					dirEntries, err := nbrew.FS.WithContext(groupctxB).ReadDir(path.Join(sitePrefix, outputDir))
					if err != nil {
						return err
					}
					subgroup, subctx := errgroup.WithContext(groupctxB)
					for _, dirEntry := range dirEntries {
						if !dirEntry.IsDir() {
							continue
						}
						name := dirEntry.Name()
						subgroup.Go(func() error {
							return nbrew.FS.WithContext(subctx).RemoveAll(path.Join(sitePrefix, outputDir, name))
						})
					}
					return subgroup.Wait()
				}
				return nil
			})
		}
		err = groupB.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}

		// 1. delete files
		// 2. delete outputDir (if an entire post category was deleted, we also delete the entire output/posts/{category})
		// 3. if index.html | 404.html was deleted, fill them in with embed/index.html | embed/404.html and regenerate the pages
		// 4. if post.html was deleted, fill it in with embed/post.html and regenerate all posts for the category
		// 5. if (postlist.html was deleted or a post was deleted), if (postlist.html was deleted) fill it in with embed/postlist.html. then, regenerate the postlist for the category
		// 6. if a page was deleted, regenerate the parent page
		// 7. if a page asset (markdown file or image) was deleted, regenerate the parent page
		// 8. if a post image was deleted, regenerate the parent post
		groupC, groupctxC := errgroup.WithContext(r.Context())
		var indexHTML string
		if resetIndexHTML.Load() {
			groupC.Go(func() error {
				b, err := fs.ReadFile(RuntimeFS, "embed/index.html")
				if err != nil {
					return err
				}
				indexHTML = string(b)
				writer, err := nbrew.FS.WithContext(groupctxC).OpenWriter(path.Join(sitePrefix, "pages/index.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
		}
		var x404HTML string
		if reset404HTML.Load() {
			groupC.Go(func() error {
				b, err := fs.ReadFile(RuntimeFS, "embed/404.html")
				if err != nil {
					return err
				}
				x404HTML = string(b)
				writer, err := nbrew.FS.WithContext(groupctxC).OpenWriter(path.Join(sitePrefix, "pages/404.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
		}
		if restoreCategoryPostHTML.Load() != nil {
			groupC.Go(func() error {
				category := *restoreCategoryPostHTML.Load()
				b, err := fs.ReadFile(RuntimeFS, "embed/post.html")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctxC).OpenWriter(path.Join(sitePrefix, "posts", category, "post.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
		}
		if restoreCategoryPostListHTML.Load() != nil {
			groupC.Go(func() error {
				category := *restoreCategoryPostListHTML.Load()
				b, err := fs.ReadFile(RuntimeFS, "embed/postlist.html")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctxC).OpenWriter(path.Join(sitePrefix, "posts", category, "postlist.html"), 0644)
				if err != nil {
					return err
				}
				defer writer.Close()
				_, err = writer.Write(b)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				return nil
			})
		}
		err = groupC.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}

		if resetIndexHTML.Load() ||
			reset404HTML.Load() ||
			regenerateCategoryPosts.Load() != nil ||
			regenerateCategoryPostList.Load() != nil ||
			regenerateParentPage.Load() != nil ||
			regenerateParentPost.Load() != nil {
			var templateErrPtr atomic.Pointer[TemplateError]
			siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			regenerationCount := atomic.Int64{}
			startedAt := time.Now()
			groupD, groupctxD := errgroup.WithContext(r.Context())
			if resetIndexHTML.Load() {
				groupD.Go(func() error {
					err := siteGen.GeneratePage(groupctxD, "pages/index.html", indexHTML)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			if reset404HTML.Load() {
				groupD.Go(func() error {
					err := siteGen.GeneratePage(groupctxD, "pages/404.html", x404HTML)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			if regenerateCategoryPosts.Load() != nil {
				groupD.Go(func() error {
					category := *regenerateCategoryPosts.Load()
					tmpl, err := siteGen.PostTemplate(groupctxD, category)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					n, err := siteGen.GeneratePosts(groupctxD, category, tmpl)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(int64(n))
					return nil
				})
			}
			if regenerateCategoryPostList.Load() != nil {
				groupD.Go(func() error {
					category := *regenerateCategoryPostList.Load()
					tmpl, err := siteGen.PostListTemplate(groupctxD, category)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					n, err := siteGen.GeneratePostList(groupctxD, category, tmpl)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(int64(n))
					return nil
				})
			}
			if regenerateParentPage.Load() != nil {
				groupD.Go(func() error {
					filePath := *regenerateParentPage.Load()
					file, err := nbrew.FS.WithContext(groupctxD).Open(path.Join(sitePrefix, filePath))
					if err != nil {
						if errors.Is(err, fs.ErrNotExist) {
							return nil
						}
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
					err = siteGen.GeneratePage(groupctxD, filePath, b.String())
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			if regenerateParentPost.Load() != nil {
				groupD.Go(func() error {
					filePath := *regenerateParentPost.Load()
					category := path.Dir(strings.TrimPrefix(filePath, "posts/"))
					if category == "." {
						category = ""
					}
					tmpl, err := siteGen.PostTemplate(groupctxD, category)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					file, err := nbrew.FS.WithContext(groupctxD).Open(path.Join(sitePrefix, filePath))
					if err != nil {
						if errors.Is(err, fs.ErrNotExist) {
							return nil
						}
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
					var creationTime time.Time
					if fileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
						creationTime = fileInfo.CreationTime
					} else {
						var absolutePath string
						if dirFS, ok := nbrew.FS.(*DirFS); ok {
							absolutePath = path.Join(dirFS.RootDir, sitePrefix, filePath)
						}
						creationTime = CreationTime(absolutePath, fileInfo)
					}
					err = siteGen.GeneratePost(groupctxD, filePath, b.String(), creationTime, tmpl)
					if err != nil {
						var templateErr TemplateError
						if errors.As(err, &templateErr) {
							templateErrPtr.CompareAndSwap(nil, &templateErr)
							return nil
						}
						return err
					}
					regenerationCount.Add(1)
					return nil
				})
			}
			err = groupD.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			response.RegenerationStats.Count = regenerationCount.Load()
			response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
			if templateErrPtr.Load() != nil {
				response.RegenerationStats.TemplateError = *templateErrPtr.Load()
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
		nbrew.methodNotAllowed(w, r)
	}
}
