package nb10

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"runtime/debug"
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

func (nbrew *Notebrew) siteJSON(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
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
		ContentBaseURL    string            `json:"contentBaseURL"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		DisableReason     string            `json:"disableReason"`
		Title             string            `json:"title"`
		Emoji             string            `json:"emoji"`
		Favicon           string            `json:"favicon"`
		CodeStyle         string            `json:"codeStyle"`
		Description       string            `json:"description"`
		NavigationLinks   []NavigationLink  `json:"navigationLinks"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
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
		var home string
		siteName := strings.TrimPrefix(sitePrefix, "@")
		if siteName == "" {
			home = "home"
		} else if strings.Contains(siteName, ".") {
			home = siteName
		} else {
			home = siteName + "." + nbrew.ContentDomain
		}
		if len(request.NavigationLinks) == 0 {
			request.NavigationLinks = []NavigationLink{
				{Name: home, URL: "/"},
				{Name: "posts", URL: "/posts/"},
			}
		}
		return request
	}

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if r.Method == "HEAD" {
					w.WriteHeader(http.StatusOK)
					return
				}
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			referer := nbrew.GetReferer(r)
			funcMap := map[string]any{
				"join":                  path.Join,
				"base":                  path.Base,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"contains":              strings.Contains,
				"humanReadableFileSize": HumanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
				"chromaStyles":          func() map[string]bool { return chromaStyles },
				"incr":                  func(n int) int { return n + 1 },
			}
			tmpl, err := template.New("site_json.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/site_json.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}
		var response Response
		_, err := nbrew.GetSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.ClearSession(w, r, "flash")
		response.ContentBaseURL = nbrew.ContentBaseURL(sitePrefix)
		_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.SitePrefix = sitePrefix
		b, err := fs.ReadFile(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "site.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		var request Request
		if len(b) > 0 {
			err := json.Unmarshal(b, &request)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
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
		if user.DisableReason != "" {
			nbrew.AccountDisabled(w, r, user.DisableReason)
			return
		}
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
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
			err := nbrew.SetSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "site.json",
				},
				"regenerationStats": response.RegenerationStats,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
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
				nbrew.BadRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
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
			nbrew.UnsupportedContentType(w, r)
			return
		}

		request = normalizeRequest(request)
		b, err := json.MarshalIndent(&request, "", "  ")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, "site.json"), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.Copy(writer, bytes.NewReader(b))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		err = writer.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		regenerationStats, err := nbrew.RegenerateSite(r.Context(), sitePrefix)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		response := Response{
			ContentBaseURL:    nbrew.ContentBaseURL(sitePrefix),
			UserID:            user.UserID,
			Username:          user.Username,
			SitePrefix:        sitePrefix,
			Title:             request.Title,
			Emoji:             request.Emoji,
			Favicon:           request.Favicon,
			CodeStyle:         request.CodeStyle,
			Description:       request.Description,
			NavigationLinks:   request.NavigationLinks,
			RegenerationStats: regenerationStats,
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}

type RegenerationStats struct {
	Count         int64         `json:"count"`
	TimeTaken     string        `json:"timeTaken"`
	TemplateError TemplateError `json:"templateError"`
}

func (nbrew *Notebrew) RegenerateSite(ctx context.Context, sitePrefix string) (RegenerationStats, error) {
	siteGen, err := NewSiteGenerator(ctx, SiteGeneratorConfig{
		FS:                 nbrew.FS,
		ContentDomain:      nbrew.ContentDomain,
		ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
		ImgDomain:          nbrew.ImgDomain,
		SitePrefix:         sitePrefix,
	})
	if err != nil {
		return RegenerationStats{}, err
	}
	rootPagesDir := path.Join(sitePrefix, "pages")
	rootPostsDir := path.Join(sitePrefix, "posts")
	postTemplate, err := siteGen.PostTemplate(ctx, "")
	if err != nil {
		return RegenerationStats{}, err
	}
	postTemplates := map[string]*template.Template{
		"": postTemplate,
	}
	postListTemplate, err := siteGen.PostListTemplate(ctx, "")
	if err != nil {
		return RegenerationStats{}, err
	}
	postListTemplates := map[string]*template.Template{
		"": postListTemplate,
	}
	var regenerationStats RegenerationStats
	var regenerationCount atomic.Int64
	startedAt := time.Now()

	if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
		type File struct {
			FilePath     string
			Text         string
			CreationTime time.Time
		}
		group, groupctx := errgroup.WithContext(ctx)
		group.Go(func() (err error) {
			defer func() {
				if v := recover(); v != nil {
					err = fmt.Errorf("panic: " + string(debug.Stack()))
				}
			}()
			cursor, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE file_path LIKE {pattern} ESCAPE '\\'" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.html'",
				Values: []any{
					sq.StringParam("pattern", wildcardReplacer.Replace(rootPagesDir)+"/%"),
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
				subgroup.Go(func() (err error) {
					defer func() {
						if v := recover(); v != nil {
							err = fmt.Errorf("panic: " + string(debug.Stack()))
						}
					}()
					if sitePrefix != "" {
						_, file.FilePath, _ = strings.Cut(file.FilePath, "/")
					}
					err = siteGen.GeneratePage(subctx, file.FilePath, file.Text)
					if err != nil {
						return err
					}
					regenerationCount.Add(1)
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
		group.Go(func() (err error) {
			defer func() {
				if v := recover(); v != nil {
					err = fmt.Errorf("panic: " + string(debug.Stack()))
				}
			}()
			cursorA, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {postsDir})" +
					" AND is_dir",
				Values: []any{
					sq.StringParam("postsDir", rootPostsDir),
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
			cursorB, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE file_path LIKE {pattern} ESCAPE '\\'" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.md'",
				Values: []any{
					sq.StringParam("pattern", wildcardReplacer.Replace(rootPostsDir)+"/%"),
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
					regenerationCount.Add(1)
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
					regenerationCount.Add(int64(n))
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
			if !errors.As(err, &regenerationStats.TemplateError) {
				return RegenerationStats{}, nil
			}
		}
		regenerationStats.Count = regenerationCount.Load()
		regenerationStats.TimeTaken = time.Since(startedAt).String()
		return regenerationStats, nil
	}

	group, groupctx := errgroup.WithContext(ctx)
	group.Go(func() (err error) {
		defer func() {
			if v := recover(); v != nil {
				err = fmt.Errorf("panic: " + string(debug.Stack()))
			}
		}()
		subgroup, subctx := errgroup.WithContext(groupctx)
		err = fs.WalkDir(nbrew.FS.WithContext(groupctx), rootPagesDir, func(filePath string, dirEntry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if filePath == rootPagesDir {
				return nil
			}
			subgroup.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
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
				regenerationCount.Add(1)
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
	group.Go(func() (err error) {
		defer func() {
			if v := recover(); v != nil {
				err = fmt.Errorf("panic: " + string(debug.Stack()))
			}
		}()
		dirEntries, err := nbrew.FS.WithContext(groupctx).ReadDir(rootPostsDir)
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
		err = fs.WalkDir(nbrew.FS.WithContext(groupctx), rootPostsDir, func(filePath string, dirEntry fs.DirEntry, err error) error {
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
				if dirFS, ok := nbrew.FS.(*DirFS); ok {
					absolutePath = path.Join(dirFS.RootDir, sitePrefix, filePath)
				}
				creationTime := CreationTime(absolutePath, fileInfo)
				err = siteGen.GeneratePost(subctxB, filePath, b.String(), creationTime, postTemplate)
				if err != nil {
					return err
				}
				regenerationCount.Add(1)
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
				regenerationCount.Add(int64(n))
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
		if !errors.As(err, &regenerationStats.TemplateError) {
			return RegenerationStats{}, err
		}
	}
	regenerationStats.Count = regenerationCount.Load()
	regenerationStats.TimeTaken = time.Since(startedAt).String()
	return regenerationStats, nil
}
