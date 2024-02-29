package nb10

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

var chromaStyles = map[string]bool{
	"abap": true, "algol": true, "algol_nu": true, "api": true, "arduino": true,
	"autumn": true, "average": true, "base16-snazzy": true, "borland": true, "bw": true,
	"catppuccin-frappe": true, "catppuccin-latte": true, "catppuccin-macchiato": true,
	"catppuccin-mocha": true, "colorful": true, "compat": true, "doom-one": true,
	"doom-one2": true, "dracula": true, "emacs": true, "friendly": true, "fruity": true,
	"github-dark": true, "github": true, "gruvbox-light": true, "gruvbox": true,
	"hr_high_contrast": true, "hrdark": true, "igor": true, "lovelace": true, "manni": true,
	"modus-operandi": true, "modus-vivendi": true, "monokai": true, "monokailight": true,
	"murphy": true, "native": true, "nord": true, "onedark": true, "onesenterprise": true,
	"paraiso-dark": true, "paraiso-light": true, "pastie": true, "perldoc": true,
	"pygments": true, "rainbow_dash": true, "rose-pine-dawn": true, "rose-pine-moon": true,
	"rose-pine": true, "rrt": true, "solarized-dark": true, "solarized-dark256": true,
	"solarized-light": true, "swapoff": true, "tango": true, "trac": true, "vim": true,
	"vs": true, "vulcan": true, "witchhazel": true, "xcode-dark": true, "xcode": true,
}

func (nbrew *Notebrew) siteJSON(w http.ResponseWriter, r *http.Request, username, sitePrefix string) {
	type NavigationLink struct {
		Name string       `json:"name"`
		URL  template.URL `json:"url"`
	}
	type Request struct {
		Title           string           `json:"title"`
		Emoji           string           `json:"emoji"`
		Favicon         string           `json:"favicon"`
		CodeStyle       string           `json:"codeStyle"`
		Description     string           `json:"description"`
		NavigationLinks []NavigationLink `json:"navigationLinks"`
	}
	type Response struct {
		PostRedirectGet map[string]any   `json:"postRedirectGet,omitempty"`
		Count           int              `json:"count"`
		TimeTaken       string           `json:"timeTaken"`
		TemplateError   TemplateError    `json:"templateError,omitempty"`
		ContentSite     string           `json:"contentSite"`
		Username        NullString       `json:"username"`
		SitePrefix      string           `json:"sitePrefix"`
		Title           string           `json:"title"`
		Emoji           string           `json:"emoji"`
		Favicon         string           `json:"favicon"`
		CodeStyle       string           `json:"codeStyle"`
		Description     string           `json:"description"`
		NavigationLinks []NavigationLink `json:"navigationLinks"`
	}
	normalizeRequest := func(request Request) Request {
		if request.Title == "" {
			request.Title = "My Blog"
		}
		if request.Emoji == "" {
			request.Emoji = "☕"
		}
		if !chromaStyles[request.CodeStyle] {
			request.CodeStyle = "onedark"
		}
		if request.Description == "" {
			request.Description = "# Hello World!\n\nWelcome to my blog."
		}
		if len(request.NavigationLinks) == 0 {
			request.NavigationLinks = []NavigationLink{
				{Name: "home", URL: "/"},
				{Name: "posts", URL: "/posts/"},
			}
		}
		return request
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
				"join":         path.Join,
				"base":         path.Base,
				"hasPrefix":    strings.HasPrefix,
				"trimPrefix":   strings.TrimPrefix,
				"contains":     strings.Contains,
				"stylesCSS":    func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS":   func() template.JS { return template.JS(baselineJS) },
				"referer":      func() string { return referer },
				"chromaStyles": func() map[string]bool { return chromaStyles },
				"incr":         func(n int) int { return n + 1 },
			}
			tmpl, err := template.New("site_json.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/site_json.html")
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
		response.Username = NullString{String: username, Valid: nbrew.DB != nil}
		response.SitePrefix = sitePrefix
		b, err := fs.ReadFile(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "site.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		var request Request
		if len(b) > 0 {
			err := json.Unmarshal(b, &request)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		request = normalizeRequest(request)
		response.Title = request.Title
		response.Emoji = request.Emoji
		response.Favicon = request.Favicon
		response.CodeStyle = request.CodeStyle
		response.Description = request.Description
		response.NavigationLinks = request.NavigationLinks
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
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "site.json",
				},
				"count":         response.Count,
				"timeTaken":     response.TimeTaken,
				"templateError": response.TemplateError,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "site.json"), http.StatusFound)
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
			request.Title = r.Form.Get("title")
			request.Emoji = r.Form.Get("emoji")
			request.Favicon = r.Form.Get("favicon")
			request.CodeStyle = r.Form.Get("codeStyle")
			request.Description = r.Form.Get("description")
			navigationLinkNames := r.Form["navigationLinkName"]
			navigationLinkURLs := r.Form["navigationLinkURL"]
			for i := range navigationLinkNames {
				if i >= len(navigationLinkURLs) {
					break
				}
				request.NavigationLinks = append(request.NavigationLinks, NavigationLink{
					Name: navigationLinkNames[i],
					URL:  template.URL(navigationLinkURLs[i]),
				})
			}
		default:
			unsupportedContentType(w, r)
			return
		}

		request = normalizeRequest(request)
		b, err := json.MarshalIndent(&request, "", "  ")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, "site.json"), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.Copy(writer, bytes.NewReader(b))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}

		if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
			type File struct {
				FilePath string
				IsDir    bool
				Text     string
			}
			var response Response
			var count atomic.Int64
			startedAt := time.Now()
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				pagesDir := path.Join(sitePrefix, "pages")
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
				postsDir := path.Join(sitePrefix, "posts")
				postTemplate, err := siteGen.PostTemplate(groupctx, "")
				if err != nil {
					return err
				}
				postTemplates := map[string]*template.Template{
					"": postTemplate,
				}
				postListTemplate, err := siteGen.PostListTemplate(groupctx, "")
				if err != nil {
					return err
				}
				postListTemplates := map[string]*template.Template{
					"": postListTemplate,
				}
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
						FilePath: row.String("file_path"),
						Text:     row.String("text"),
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
						postTemplate := postTemplates[category]
						if postTemplate == nil {
							return nil
						}
						err = siteGen.GeneratePost(subctxB, file.FilePath, file.Text, postTemplate)
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
				if !errors.As(err, &response.TemplateError) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
			response.Count = int(count.Load())
			response.TimeTaken = time.Since(startedAt).String()
			writeResponse(w, r, response)
			return
		}

		var response Response
		var count atomic.Int64
		startedAt := time.Now()
		group, groupctx := errgroup.WithContext(r.Context())
		group.Go(func() error {
			subgroup, subctx := errgroup.WithContext(groupctx)
			root := path.Join(sitePrefix, "pages")
			err := fs.WalkDir(nbrew.FS.WithContext(groupctx), root, func(filePath string, dirEntry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if filePath == root {
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
						filePath = strings.TrimPrefix(filePath, sitePrefix+"/")
					}
					count.Add(1)
					return siteGen.GeneratePage(subctx, filePath, b.String())
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
			postTemplate, err := siteGen.PostTemplate(groupctx)
			if err != nil {
				return err
			}
			subgroup, subctx := errgroup.WithContext(groupctx)
			root := path.Join(sitePrefix, "posts")
			err = fs.WalkDir(nbrew.FS.WithContext(groupctx), root, func(filePath string, dirEntry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				subgroup.Go(func() error {
					if !dirEntry.IsDir() {
						if !strings.HasSuffix(filePath, ".md") {
							return nil
						}
						file, err := nbrew.FS.WithContext(subctx).Open(filePath)
						if err != nil {
							return err
						}
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
						if sitePrefix != "" {
							filePath = strings.TrimPrefix(filePath, sitePrefix+"/")
						}
						count.Add(1)
						return siteGen.GeneratePost(subctx, filePath, b.String(), postTemplate)
					}
					if sitePrefix != "" {
						filePath = strings.TrimPrefix(filePath, sitePrefix+"/")
					}
					_, category, _ := strings.Cut(filePath, "/")
					if strings.Contains(category, "/") {
						return nil
					}
					postListTemplate, err := siteGen.PostListTemplate(subctx, category)
					if err != nil {
						return err
					}
					n, err := siteGen.GeneratePostList(subctx, category, postListTemplate)
					count.Add(int64(n))
					if err != nil {
						return err
					}
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
		err = group.Wait()
		response.Count = int(count.Load())
		response.TimeTaken = time.Since(startedAt).String()
		if err != nil && !errors.As(err, &response.TemplateError) {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
