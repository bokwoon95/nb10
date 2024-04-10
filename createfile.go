package nb10

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yuin/goldmark"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) createfile(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		Parent  string
		Name    string
		Ext     string
		Content string
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		Parent            string            `json:"parent"`
		Name              string            `json:"name"`
		Ext               string            `json:"ext"`
		Content           string            `json:"content"`
		Error             string            `json:"error"`
		FormErrors        url.Values        `json:"formErrors"`
		UploadCount       int64             `json:"uploadCount"`
		UploadSize        int64             `json:"uploadSize"`
		FilesTooBig       []string          `json:"filesTooBig"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
	}

	isValidParent := func(parent string) bool {
		head, tail, _ := strings.Cut(parent, "/")
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
			if next == "posts" {
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
			referer := nbrew.getReferer(r)
			funcMap := map[string]any{
				"join":       path.Join,
				"base":       path.Base,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
				"head": func(s string) string {
					head, _, _ := strings.Cut(s, "/")
					return head
				},
				"tail": func(s string) string {
					_, tail, _ := strings.Cut(s, "/")
					return tail
				},
			}
			tmpl, err := template.New("createfile.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/createfile.html")
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
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			response.Ext = ".txt"
		case "pages":
			response.Ext = ".html"
		case "posts":
			response.Ext = ".md"
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next == "themes" {
				response.Ext = ".html"
			} else {
				response.Ext = ".js"
			}
		default:
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
					nbrew.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "createfile")+"/?parent="+url.QueryEscape(response.Parent), http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "createfile",
				},
				"uploadCount":       response.UploadCount,
				"uploadSize":        response.UploadSize,
				"regenerationStats": response.RegenerationStats,
				"filesTooBig":       response.FilesTooBig,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent, response.Name+response.Ext), http.StatusFound)
		}
		if nbrew.DB != nil {
			// TODO: calculate the available storage space of the owner and add
			// it as a MaxBytesReader to the request body.
			//
			// TODO: but then: how do we differentiate between a MaxBytesError
			// returned by a file exceeding 10 MB vs a MaxBytesError returned
			// by the request body exceeding available storage space? Maybe if
			// maxBytesErr is 10 MB we assume it's a file going over the limit,
			// otherwise we assume it's the owner exceeding his storage space?
		}

		var err error
		var request Request
		var reader *multipart.Reader
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				nbrew.badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			err := r.ParseForm()
			if err != nil {
				nbrew.badRequest(w, r, err)
				return
			}
			request.Parent = r.Form.Get("parent")
			request.Name = r.Form.Get("name")
			request.Ext = r.Form.Get("ext")
			request.Content = r.Form.Get("content")
		case "multipart/form-data":
			reader, err = r.MultipartReader()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			var maxBytesErr *http.MaxBytesError
			for i := 0; i < 4; i++ {
				part, err := reader.NextPart()
				if err != nil {
					if err == io.EOF {
						break
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				var b strings.Builder
				_, err = io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
				if err != nil {
					if errors.As(err, &maxBytesErr) {
						nbrew.badRequest(w, r, err)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				formName := part.FormName()
				switch formName {
				case "parent":
					request.Parent = b.String()
				case "name":
					request.Name = b.String()
				case "ext":
					request.Ext = b.String()
				case "content":
					request.Content = b.String()
				}
			}
		default:
			nbrew.unsupportedContentType(w, r)
			return
		}

		response := Response{
			FormErrors: make(url.Values),
			Parent:     path.Clean(strings.Trim(request.Parent, "/")),
			Ext:        request.Ext,
			Content:    request.Content,
		}
		if !isValidParent(response.Parent) {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		head, tail, _ := strings.Cut(response.Parent, "/")
		switch head {
		case "notes":
			if request.Name != "" {
				response.Name = filenameSafe(request.Name)
			} else {
				if response.Ext == ".md" || response.Ext == ".txt" {
					var line string
					remainder := response.Content
					for remainder != "" {
						line, remainder, _ = strings.Cut(remainder, "\n")
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}
						if response.Ext == ".md" {
							response.Name = filenameSafe(stripMarkdownStyles(goldmark.New(), []byte(line)))
						} else {
							response.Name = filenameSafe(line)
						}
						break
					}
				}
			}
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			if response.Ext != ".html" && response.Ext != ".css" && response.Ext != ".js" && response.Ext != ".md" && response.Ext != ".txt" {
				response.Ext = ".txt"
			}
		case "pages":
			if request.Name != "" {
				response.Name = urlSafe(request.Name)
			}
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			if response.Ext != ".html" {
				response.Ext = ".html"
			}
			if response.Parent != "" && response.Name == "index" && response.Ext == ".html" {
				response.FormErrors.Add("name", "this name is not allowed")
				response.Error = "FormErrorsPresent"
				writeResponse(w, r, response)
				return
			}
		case "posts":
			if request.Name != "" {
				response.Name = urlSafe(request.Name)
			} else {
				remainder := response.Content
				for remainder != "" {
					response.Name, remainder, _ = strings.Cut(remainder, "\n")
					response.Name = strings.TrimSpace(response.Name)
					if response.Name == "" {
						continue
					}
					response.Name = urlSafe(stripMarkdownStyles(goldmark.New(), []byte(response.Name)))
					break
				}
			}
			var timestamp [8]byte
			binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
			prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			if response.Name != "" {
				response.Name = prefix + "-" + response.Name
			} else {
				response.Name = prefix
			}
			if response.Ext != ".md" {
				response.Ext = ".md"
			}
		case "output":
			if request.Name != "" {
				response.Name = urlSafe(request.Name)
			}
			if response.Name == "" {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
				response.Name = strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			}
			next, _, _ := strings.Cut(tail, "/")
			if next == "themes" {
				if response.Ext != ".html" && response.Ext != ".css" && response.Ext != ".js" && response.Ext != ".md" && response.Ext != ".txt" {
					response.Ext = ".html"
				}
			} else {
				if response.Ext != ".css" && response.Ext != ".js" && response.Ext != ".md" {
					response.Ext = ".css"
				}
			}
		default:
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, response.Parent, response.Name+response.Ext))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		} else {
			switch head {
			case "pages":
				response.FormErrors.Add("name", "page already exists")
			case "posts":
				response.FormErrors.Add("name", "post already exists")
			default:
				response.FormErrors.Add("name", "file already exists")
			}
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, response.Parent, response.Name+response.Ext), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.WriteString(writer, response.Content)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		err = writer.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		if (head == "pages" || head == "posts") && contentType == "multipart/form-data" {
			var outputDir string
			if head == "posts" {
				outputDir = path.Join(sitePrefix, "output/posts", tail, response.Name)
			} else {
				if response.Parent == "pages" && response.Name == "index" && response.Ext == ".html" {
					outputDir = path.Join(sitePrefix, "output")
				} else {
					outputDir = path.Join(sitePrefix, "output", tail, response.Name)
				}
			}
			tempDir, err := filepath.Abs(filepath.Join(os.TempDir(), "notebrew-temp"))
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			var uploadCount, uploadSize atomic.Int64
			writeFile := func(ctx context.Context, filePath string, reader io.Reader) error {
				writer, err := nbrew.FS.WithContext(ctx).OpenWriter(filePath, 0644)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return err
					}
					err := nbrew.FS.WithContext(ctx).MkdirAll(path.Dir(filePath), 0755)
					if err != nil {
						return err
					}
					writer, err = nbrew.FS.WithContext(ctx).OpenWriter(filePath, 0644)
					if err != nil {
						return err
					}
				}
				defer writer.Close()
				n, err := io.Copy(writer, reader)
				if err != nil {
					return err
				}
				err = writer.Close()
				if err != nil {
					return err
				}
				uploadCount.Add(1)
				uploadSize.Add(n)
				return nil
			}
			var timeCounter atomic.Int64
			group, groupctx := errgroup.WithContext(r.Context())
			for {
				part, err := reader.NextPart()
				if err != nil {
					if err == io.EOF {
						break
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				formName := part.FormName()
				if formName != "file" {
					continue
				}
				_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
				if err != nil {
					continue
				}
				fileName := params["filename"]
				if fileName == "" || strings.Contains(fileName, "/") {
					continue
				}
				fileName = filenameSafe(fileName)
				ext := path.Ext(fileName)
				if (ext == ".jpeg" || ext == ".jpg" || ext == ".png" || ext == ".webp" || ext == ".gif") && strings.TrimSuffix(fileName, ext) == "image" {
					var timestamp [8]byte
					now := time.Now()
					timeCounter.CompareAndSwap(0, now.Unix())
					binary.BigEndian.PutUint64(timestamp[:], uint64(max(now.Unix(), timeCounter.Add(1))))
					timestampSuffix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
					fileName = "image-" + timestampSuffix + ext
				}
				filePath := path.Join(outputDir, fileName)
				switch ext {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					if nbrew.ImgCmd == "" {
						err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, 10<<20 /* 10 MB */))
						if err != nil {
							var maxBytesErr *http.MaxBytesError
							if errors.As(err, &maxBytesErr) {
								response.FilesTooBig = append(response.FilesTooBig, fileName)
								continue
							}
							getLogger(r.Context()).Error(err.Error())
							nbrew.internalServerError(w, r, err)
							return
						}
						continue
					}
					cmdPath, err := exec.LookPath(nbrew.ImgCmd)
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					id := NewID()
					inputPath := path.Join(tempDir, id.String()+"-input"+ext)
					outputPath := path.Join(tempDir, id.String()+"-output"+ext)
					input, err := os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							getLogger(r.Context()).Error(err.Error())
							nbrew.internalServerError(w, r, err)
							return
						}
						err := os.MkdirAll(filepath.Dir(inputPath), 0755)
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							nbrew.internalServerError(w, r, err)
							return
						}
						input, err = os.OpenFile(inputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							nbrew.internalServerError(w, r, err)
							return
						}
					}
					_, err = io.Copy(input, http.MaxBytesReader(nil, part, 10<<20 /* 10 MB */))
					if err != nil {
						os.Remove(inputPath)
						var maxBytesErr *http.MaxBytesError
						if errors.As(err, &maxBytesErr) {
							response.FilesTooBig = append(response.FilesTooBig, fileName)
							continue
						}
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					err = input.Close()
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						nbrew.internalServerError(w, r, err)
						return
					}
					group.Go(func() error {
						defer os.Remove(inputPath)
						defer os.Remove(outputPath)
						cmd := exec.CommandContext(groupctx, cmdPath, inputPath, outputPath)
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
						err := cmd.Run()
						if err != nil {
							return err
						}
						output, err := os.Open(outputPath)
						if err != nil {
							return err
						}
						defer output.Close()
						err = writeFile(groupctx, filePath, output)
						if err != nil {
							return err
						}
						return nil
					})
				}
			}
			err = group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			response.UploadCount = uploadCount.Load()
			response.UploadSize = uploadSize.Load()
		}
		switch head {
		case "pages":
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
			err = siteGen.GeneratePage(r.Context(), path.Join(response.Parent, response.Name+response.Ext), response.Content)
			if err != nil {
				if !errors.As(err, &response.RegenerationStats.TemplateError) {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			}
			response.RegenerationStats.Count = 1
			response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
		case "posts":
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
			var regenerationCount atomic.Int64
			var templateErrPtr atomic.Pointer[TemplateError]
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				var templateErr TemplateError
				category := tail
				tmpl, err := siteGen.PostTemplate(groupctx, category)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				filePath := path.Join(response.Parent, response.Name+response.Ext)
				err = siteGen.GeneratePost(groupctx, filePath, response.Content, time.Now(), tmpl)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				regenerationCount.Add(1)
				return nil
			})
			group.Go(func() error {
				var templateErr TemplateError
				category := tail
				tmpl, err := siteGen.PostListTemplate(groupctx, category)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				n, err := siteGen.GeneratePostList(r.Context(), category, tmpl)
				if err != nil {
					if errors.As(err, &templateErr) {
						templateErrPtr.CompareAndSwap(nil, &templateErr)
						return nil
					}
					return err
				}
				regenerationCount.Add(int64(n))
				return nil
			})
			err = group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			response.RegenerationStats.Count = regenerationCount.Load()
			if templateErrPtr.Load() != nil {
				response.RegenerationStats.TemplateError = *templateErrPtr.Load()
			}
		}
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
