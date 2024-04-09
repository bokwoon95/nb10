package nb10

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) rename(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		Parent string `json:"parent"`
		Name   string `json:"name"`
		To     string `json:"to"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		Parent            string            `json:"parent"`
		From              string            `json:"from"`
		To                string            `json:"to"`
		Prefix            string            `json:"prefix"`
		Ext               string            `json:"ext"`
		IsDir             bool              `json:"isDir"`
		Error             string            `json:"status"`
		FormErrors        url.Values        `json:"formErrors"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
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
			referer := nbrew.getReferer(r)
			funcMap := map[string]any{
				"join":       path.Join,
				"base":       path.Base,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("rename.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/rename.html")
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
		response.UserID = user.UserID
		response.Username = user.Username
		response.SitePrefix = sitePrefix
		response.Parent = path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		name := r.Form.Get("name")
		if name == "" || strings.Contains(name, "/") {
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		head, _, _ := strings.Cut(response.Parent, "/")
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		response.IsDir = fileInfo.IsDir()
		if response.IsDir {
			response.From = name
		} else {
			remainder := name
			if head == "posts" {
				i := strings.Index(remainder, "-")
				if i >= 0 {
					prefix, suffix := remainder[:i], remainder[i+1:]
					if len(prefix) > 0 && len(prefix) <= 8 {
						b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
						if len(b) == 5 {
							response.Prefix = prefix + "-"
							remainder = suffix
						}
					}
				} else {
					prefix := strings.TrimSuffix(remainder, path.Ext(remainder))
					if len(prefix) > 0 && len(prefix) <= 8 {
						b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
						if len(b) == 5 {
							response.Prefix = prefix + "-"
							remainder = path.Ext(remainder)
						}
					}
				}
			}
			ext := path.Ext(remainder)
			response.From = strings.TrimSuffix(remainder, ext)
			response.Ext = ext
		}
		switch head {
		case "notes", "pages", "posts", "output":
			if response.Parent == "pages" && (name == "index.html" || name == "404.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			if response.Parent == "output/themes" && (name == "post.html" || name == "postlist.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
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
				redirectURL := "/" + path.Join("files", sitePrefix, "rename") + "/" +
					"?parent=" + url.QueryEscape(response.Parent) +
					"&name=" + url.QueryEscape(response.Prefix+response.From+response.Ext)
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":    "rename",
					"parent":  response.Parent,
					"oldName": response.Prefix + response.From + response.Ext,
					"newName": response.Prefix + response.To + response.Ext,
					"isDir":   response.IsDir,
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
			request.Name = r.Form.Get("name")
			request.To = r.Form.Get("to")
		default:
			nbrew.unsupportedContentType(w, r)
			return
		}

		response := Response{
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			To:         request.To,
			FormErrors: make(url.Values),
		}
		if request.Name == "" || strings.Contains(request.Name, "/") {
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, response.Parent, request.Name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		response.IsDir = fileInfo.IsDir()
		if response.IsDir {
			response.From = request.Name
		} else {
			remainder := request.Name
			ext := path.Ext(remainder)
			if head == "posts" && ext == ".md" {
				prefix, suffix, ok := strings.Cut(remainder, "-")
				if ok {
					if len(prefix) > 0 && len(prefix) <= 8 {
						b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
						if len(b) == 5 {
							response.Prefix = prefix + "-"
							remainder = suffix
						}
					}
				} else {
					prefix := strings.TrimSuffix(remainder, ext)
					if len(prefix) > 0 && len(prefix) <= 8 {
						b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
						if len(b) == 5 {
							response.Prefix = prefix + "-"
							remainder = ext
						}
					}
				}
			}
			response.From = strings.TrimSuffix(remainder, ext)
			response.Ext = ext
		}
		if response.To == "" {
			response.FormErrors.Add("to", fmt.Sprintf("cannot be empty"))
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		switch head {
		case "notes":
			for _, char := range response.To {
				if char >= 0 && char <= 31 {
					continue
				}
				n := int(char)
				if n >= len(isFilenameUnsafe) || !isFilenameUnsafe[n] {
					continue
				}
				response.FormErrors.Add("to", fmt.Sprintf("cannot include character %q", string(char)))
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		case "pages", "posts", "output":
			if response.Parent == "pages" && (request.Name == "index.html" || request.Name == "404.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			if response.Parent == "output/themes" && (request.Name == "post.html" || request.Name == "postlist.html") {
				response.Error = "InvalidFile"
				writeResponse(w, r, response)
				return
			}
			for _, char := range response.To {
				if char >= 0 && char <= 31 {
					continue
				}
				n := int(char)
				if n >= len(isURLUnsafe) || !isURLUnsafe[n] {
					continue
				}
				if char == ' ' {
					response.FormErrors.Add("to", fmt.Sprintf("cannot include space"))
				} else {
					response.FormErrors.Add("to", fmt.Sprintf("cannot include character %q", string(char)))
				}
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		default:
			response.Error = "InvalidFile"
			writeResponse(w, r, response)
			return
		}
		oldName := path.Join(sitePrefix, response.Parent, response.Prefix+response.From+response.Ext)
		newName := path.Join(sitePrefix, response.Parent, response.Prefix+response.To+response.Ext)
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), newName)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		} else {
			response.FormErrors.Add("to", "a file with this name already exists")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		err = nbrew.FS.WithContext(r.Context()).Rename(oldName, newName)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		switch head {
		case "pages":
			var counterpart string
			if !response.IsDir {
				counterpart = strings.TrimPrefix(oldName, ".html")
			} else {
				counterpart = oldName + ".html"
			}
			var counterpartExists bool
			counterpartFileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), counterpart)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			} else {
				counterpartExists = true
			}
			oldOutputDir := path.Join(sitePrefix, "output", tail, response.From)
			newOutputDir := path.Join(sitePrefix, "output", tail, response.To)
			if !counterpartExists || counterpartFileInfo.IsDir() == response.IsDir {
				err := nbrew.FS.WithContext(r.Context()).Rename(oldOutputDir, newOutputDir)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				writeResponse(w, r, response)
				return
			}
			err = nbrew.FS.WithContext(r.Context()).MkdirAll(newOutputDir, 0755)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(oldOutputDir)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			group, groupctx := errgroup.WithContext(r.Context())
			for _, dirEntry := range dirEntries {
				if dirEntry.IsDir() == response.IsDir {
					name := dirEntry.Name()
					group.Go(func() error {
						return nbrew.FS.WithContext(groupctx).Rename(path.Join(oldOutputDir, name), path.Join(newOutputDir, name))
					})
				}
			}
			err = group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			var parentPage string
			if response.Parent == "pages" {
				parentPage = "pages/index.html"
			} else {
				parentPage = response.Parent + ".html"
			}
			file, err := nbrew.FS.WithContext(r.Context()).Open(parentPage)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					writeResponse(w, r, response)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			fileInfo, err := file.Stat()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
				FS:                 nbrew.FS,
				ContentDomain:      nbrew.ContentDomain,
				ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
				ImgDomain:          nbrew.ImgDomain,
				SitePrefix:         sitePrefix,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			startedAt := time.Now()
			err = siteGen.GeneratePage(r.Context(), parentPage, b.String())
			if err != nil {
				if errors.As(err, &response.RegenerationStats.TemplateError) {
					writeResponse(w, r, response)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			response.RegenerationStats.Count = 1
			response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
		case "posts":
			oldOutputDir := path.Join(sitePrefix, "output/posts", tail, response.Prefix+response.From)
			newOutputDir := path.Join(sitePrefix, "output/posts", tail, response.Prefix+response.To)
			err = nbrew.FS.WithContext(r.Context()).Rename(oldOutputDir, newOutputDir)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		case "output":
			if fileInfo.IsDir() {
				writeResponse(w, r, response)
				return
			}
			next, _, _ := strings.Cut(tail, "/")
			if next == "posts" {
				switch response.Ext {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					parentPost := tail + ".md"
					file, err := nbrew.FS.WithContext(r.Context()).Open(parentPost)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					fileInfo, err := file.Stat()
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					var creationTime time.Time
					if fileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
						creationTime = fileInfo.CreationTime
					} else {
						var absolutePath string
						if dirFS, ok := nbrew.FS.(*DirFS); ok {
							absolutePath = path.Join(dirFS.RootDir, sitePrefix, parentPost)
						}
						creationTime = CreationTime(absolutePath, fileInfo)
					}
					siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
						FS:                 nbrew.FS,
						ContentDomain:      nbrew.ContentDomain,
						ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
						ImgDomain:          nbrew.ImgDomain,
						SitePrefix:         sitePrefix,
					})
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					category := path.Dir(strings.TrimPrefix(parentPost, "posts/"))
					if category == "." {
						category = ""
					}
					startedAt := time.Now()
					tmpl, err := siteGen.PostTemplate(r.Context(), category)
					if err != nil {
						if errors.As(err, &response.RegenerationStats.TemplateError) {
							writeResponse(w, r, response)
							return
						}
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					err = siteGen.GeneratePost(r.Context(), parentPost, b.String(), creationTime, tmpl)
					if err != nil {
						if errors.As(err, &response.RegenerationStats.TemplateError) {
							writeResponse(w, r, response)
							return
						}
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					response.RegenerationStats.Count = 1
					response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				}
			} else if next != "themes" {
				switch response.Ext {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif", ".md":
					var parentPage string
					if tail == "" {
						parentPage = "pages/index.html"
					} else {
						parentPage = path.Join("pages", tail+".html")
					}
					file, err := nbrew.FS.WithContext(r.Context()).Open(parentPage)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					fileInfo, err := file.Stat()
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					var b strings.Builder
					b.Grow(int(fileInfo.Size()))
					_, err = io.Copy(&b, file)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
						FS:                 nbrew.FS,
						ContentDomain:      nbrew.ContentDomain,
						ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
						ImgDomain:          nbrew.ImgDomain,
						SitePrefix:         sitePrefix,
					})
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					startedAt := time.Now()
					err = siteGen.GeneratePage(r.Context(), parentPage, b.String())
					if err != nil {
						if errors.As(err, &response.RegenerationStats.TemplateError) {
							writeResponse(w, r, response)
							return
						}
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					response.RegenerationStats.Count = 1
					response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				}
			}
		}
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
