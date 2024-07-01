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
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) uploadfile(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Response struct {
		Error             string            `json:"error"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		Parent            string            `json:"parent"`
		UploadCount       int64             `json:"uploadCount"`
		UploadSize        int64             `json:"uploadSize"`
		FilesExist        []string          `json:"fileExist"`
		FilesTooBig       []string          `json:"filesTooBig"`
	}
	if r.Method != "POST" {
		nbrew.methodNotAllowed(w, r)
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
		err := nbrew.setSession(w, r, "flash", map[string]any{
			"postRedirectGet": map[string]any{
				"from":              "uploadfile",
				"regenerationStats": response.RegenerationStats,
				"error":             response.Error,
				"uploadCount":       response.UploadCount,
				"uploadSize":        response.UploadSize,
				"filesExist":        response.FilesExist,
				"filesTooBig":       response.FilesTooBig,
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix, response.Parent)+"/", http.StatusFound)
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

	reader, err := r.MultipartReader()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	var response Response
	part, err := reader.NextPart()
	if err != nil {
		if err == io.EOF {
			response.Error = "ParentNotFound"
			writeResponse(w, r, response)
			return
		}
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	formName := part.FormName()
	if formName != "parent" {
		response.Error = "ParentNotFound"
		writeResponse(w, r, response)
		return
	}
	var b strings.Builder
	_, err = io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			nbrew.badRequest(w, r, err)
			return
		}
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	response.Parent = b.String()

	var siteGen *SiteGenerator
	var postTemplate *template.Template
	var templateErrPtr atomic.Pointer[TemplateError]
	head, tail, _ := strings.Cut(response.Parent, "/")
	switch head {
	case "notes":
		break
	case "pages":
		siteGen, err = NewSiteGenerator(r.Context(), SiteGeneratorConfig{
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
	case "posts":
		siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
			FS:                 nbrew.FS,
			ContentDomain:      nbrew.ContentDomain,
			ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
			ImgDomain:          nbrew.ImgDomain,
			SitePrefix:         sitePrefix,
		})
		category := tail
		postTemplate, err = siteGen.PostTemplate(r.Context(), category)
		if err != nil {
			var templateErr TemplateError
			if !errors.As(err, &templateErr) {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			templateErrPtr.CompareAndSwap(nil, &templateErr)
		}
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		if next != "themes" {
			response.Error = "InvalidParent"
			writeResponse(w, r, response)
			return
		}
	case "imports":
		break
	default:
		response.Error = "InvalidParent"
		writeResponse(w, r, response)
		return
	}

	var regenerationCount, uploadCount, uploadSize atomic.Int64
	writeFile := func(ctx context.Context, filePath string, reader io.Reader) error {
		writer, err := nbrew.FS.WithContext(ctx).OpenWriter(filePath, 0644)
		if err != nil {
			return err
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

	tempDir, err := filepath.Abs(filepath.Join(os.TempDir(), "notebrew-temp"))
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	var monotonicCounter atomic.Int64
	group, groupctx := errgroup.WithContext(r.Context())
	startedAt := time.Now()
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
			monotonicCounter.CompareAndSwap(0, now.Unix())
			binary.BigEndian.PutUint64(timestamp[:], uint64(max(now.Unix(), monotonicCounter.Add(1))))
			timestampSuffix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
			fileName = "image-" + timestampSuffix + ext
		}
		filePath := path.Join(sitePrefix, response.Parent, fileName)
		_, err = fs.Stat(nbrew.FS.WithContext(r.Context()), filePath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		} else {
			response.FilesExist = append(response.FilesExist, fileName)
			continue
		}

		// Since we don't do any image processing or page/post generation
		// for notes, we can stream the file directly into the filesystem.
		if head == "notes" {
			switch ext {
			case ".jpeg", ".jpg", ".png", ".webp", ".gif":
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
			case ".html", ".css", ".js", ".md", ".txt":
				err := writeFile(r.Context(), path.Join(sitePrefix, response.Parent, fileName), http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
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
			}
			continue
		}

		if head == "pages" {
			if ext != ".html" {
				continue
			}
			if tail == "" && (fileName == "posts.html" || fileName == "themes.html") {
				continue
			}
			var b strings.Builder
			_, err := io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
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
			text := b.String()
			group.Go(func() error {
				err := writeFile(groupctx, filePath, strings.NewReader(text))
				if err != nil {
					return err
				}
				err = siteGen.GeneratePage(groupctx, filePath, text)
				if err != nil {
					var templateErr TemplateError
					if !errors.As(err, &templateErr) {
						return err
					}
					templateErrPtr.CompareAndSwap(nil, &templateErr)
				}
				regenerationCount.Add(1)
				return nil
			})
			continue
		}

		if head == "posts" {
			if ext != ".md" {
				switch fileName {
				case "postlist.json", "postlist.html", "post.html":
					break
				default:
					continue
				}
			}
			var b strings.Builder
			_, err := io.Copy(&b, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
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
			text := b.String()
			now := time.Now()
			monotonicCounter.CompareAndSwap(0, now.Unix())
			creationTime := time.Unix(max(now.Unix(), monotonicCounter.Add(1)), 0)
			group.Go(func() error {
				var timestamp [8]byte
				binary.BigEndian.PutUint64(timestamp[:], uint64(creationTime.Unix()))
				prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
				if strings.TrimSuffix(fileName, ext) != "" {
					fileName = prefix + "-" + fileName
				} else {
					fileName = prefix + fileName
				}
				filePath := path.Join(sitePrefix, response.Parent, fileName)
				err := writeFile(groupctx, filePath, strings.NewReader(text))
				if err != nil {
					return err
				}
				err = siteGen.GeneratePost(groupctx, filePath, text, creationTime, postTemplate)
				if err != nil {
					var templateErr TemplateError
					if !errors.As(err, &templateErr) {
						return err
					}
					templateErrPtr.CompareAndSwap(nil, &templateErr)
				}
				regenerationCount.Add(1)
				return nil
			})
			continue
		}

		if head == "imports" {
			if ext != ".tgz" {
				continue
			}
			err := writeFile(r.Context(), filePath, part)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			continue
		}

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
				err = writeFile(groupctx, filePath, output)
				if err != nil {
					return err
				}
				return nil
			})
			continue
		case ".html", ".css", ".js", ".md", ".txt":
			err := writeFile(r.Context(), filePath, http.MaxBytesReader(nil, part, 1<<20 /* 1 MB */))
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
	}
	err = group.Wait()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	timeTaken := time.Since(startedAt)
	if head == "posts" {
		category := tail
		err := func() error {
			postListTemplate, err := siteGen.PostListTemplate(r.Context(), category)
			if err != nil {
				return err
			}
			_, err = siteGen.GeneratePostList(r.Context(), category, postListTemplate)
			if err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			var templateErr TemplateError
			if !errors.As(err, &templateErr) {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			templateErrPtr.CompareAndSwap(nil, &templateErr)
		}
	}
	response.UploadCount = uploadCount.Load()
	response.UploadSize = uploadSize.Load()
	response.RegenerationStats.Count = regenerationCount.Load()
	if response.RegenerationStats.Count != 0 {
		response.RegenerationStats.TimeTaken = timeTaken.String()
	}
	if templateErrPtr.Load() != nil {
		response.RegenerationStats.TemplateError = *templateErrPtr.Load()
	}
	writeResponse(w, r, response)
}
