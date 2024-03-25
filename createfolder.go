package nb10

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) createfolder(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		Parent string `json:"parent"`
		Name   string `json:"name"`
	}
	type Response struct {
		ContentBaseURL string     `json:"contentBaseURL"`
		SitePrefix     string     `json:"sitePrefix"`
		UserID         ID         `json:"userID"`
		Username       string     `json:"username"`
		Parent         string     `json:"parent"`
		Name           string     `json:"name"`
		Error          string     `json:"error"`
		FormErrors     url.Values `json:"formErrors"`
	}

	isValidParent := func(parent string) bool {
		head, tail, _ := strings.Cut(parent, "/")
		if head == "posts" && tail != "" {
			return false
		}
		switch head {
		case "notes", "pages", "posts":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, parent))
			if err != nil {
				return false
			}
			if fileInfo.IsDir() {
				return true
			}
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next != "themes" {
				return false
			}
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
				"base":       path.Base,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("createfolder.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/createfolder.html")
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
		response.ContentBaseURL = nbrew.contentBaseURL(sitePrefix)
		response.SitePrefix = sitePrefix
		response.UserID = user.UserID
		response.Username = user.Username
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
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "createfolder")+"/?parent="+url.QueryEscape(response.Parent), http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":   "createfolder",
					"parent": response.Parent,
					"name":   response.Name,
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
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
			request.Name = r.Form.Get("name")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Name:       urlSafe(request.Name),
			FormErrors: make(url.Values),
		}
		if !isValidParent(response.Parent) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		if response.Name == "" {
			response.FormErrors.Add("name", "required")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		_, ok := fileTypes[path.Ext(response.Name)]
		if ok {
			response.FormErrors.Add("name", "cannot end in a file extension")
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "pages":
			err := nbrew.FS.MkdirAll(path.Join(sitePrefix, "output", tail, response.Name), 0755)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		case "posts":
			err := nbrew.FS.MkdirAll(path.Join(sitePrefix, "output", response.Parent, response.Name), 0755)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		err := nbrew.FS.Mkdir(path.Join(sitePrefix, response.Parent, response.Name), 0755)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				if head == "posts" {
					response.FormErrors.Add("name", "category already exists")
				} else {
					response.FormErrors.Add("name", "folder already exists")
				}
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if response.Parent == "posts" {
			category := response.Name
			siteGen, err := NewSiteGenerator(r.Context(), nbrew.FS, sitePrefix, nbrew.ContentDomain, nbrew.ImgDomain)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				b, err := fs.ReadFile(RuntimeFS, "embed/post.html")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, response.Parent, category, "post.html"), 0644)
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
			group.Go(func() error {
				b, err := fs.ReadFile(RuntimeFS, "embed/postlist.html")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, response.Parent, category, "postlist.html"), 0644)
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
				tmpl, err := siteGen.ParseTemplate(groupctx, path.Join("posts", category, "postlist.html"), string(b))
				if err != nil {
					return err
				}
				err = siteGen.GeneratePostListPage(groupctx, category, tmpl, 1, 1, nil)
				if err != nil {
					return err
				}
				return nil
			})
			group.Go(func() error {
				b, err := fs.ReadFile(RuntimeFS, "embed/postlist.json")
				if err != nil {
					return err
				}
				writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, response.Parent, category, "postlist.json"), 0644)
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
			err = group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
