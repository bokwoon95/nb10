package nb10

import (
	"context"
	"database/sql"
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

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

var urlReplacer = strings.NewReplacer("#", "%23", "%", "%25")

func (nbrew *Notebrew) file(w http.ResponseWriter, r *http.Request, user User, sitePrefix, filePath string, file fs.File, fileInfo fs.FileInfo) {
	type Asset struct {
		FileID       ID        `json:"fileID"`
		Parent       string    `json:"parent"`
		Name         string    `json:"name"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
		Content      string    `json:"content"`
		AltText      string    `json:"altText"`
	}
	type Response struct {
		ContentBaseURL    string            `json:"contentBaseURL"`
		ImgDomain         string            `json:"imgDomain"`
		IsDatabaseFS      bool              `json:"isDatabaseFS"`
		SitePrefix        string            `json:"sitePrefix"`
		UserID            ID                `json:"userID"`
		Username          string            `json:"username"`
		FileID            ID                `json:"fileID"`
		FilePath          string            `json:"filePath"`
		IsDir             bool              `json:"isDir"`
		ModTime           time.Time         `json:"modTime"`
		CreationTime      time.Time         `json:"creationTime"`
		Size              int64             `json:"size"`
		Content           string            `json:"content"`
		URL               template.URL      `json:"url"`
		BelongsTo         string            `json:"belongsTo"`
		AssetDir          string            `json:"assetDir"`
		PinnedAssets      []Asset           `json:"pinnedAssets"`
		Assets            []Asset           `json:"assets"`
		UploadCount       int64             `json:"uploadCount"`
		UploadSize        int64             `json:"uploadSize"`
		FilesExist        []string          `json:"filesExist"`
		FilesTooBig       []string          `json:"filesTooBig"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}

	fileType, ok := fileTypes[path.Ext(filePath)]
	if !ok {
		nbrew.notFound(w, r)
		return
	}

	// Figure out if the file is a user-editable file.
	var isEditable bool
	head, tail, _ := strings.Cut(filePath, "/")
	switch head {
	case "":
		nbrew.notFound(w, r)
		return
	case "notes":
		isEditable = fileType.Ext == ".html" || fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" || fileType.Ext == ".txt"
	case "pages":
		isEditable = fileType.Ext == ".html"
	case "posts":
		parent := path.Dir(tail)
		name := path.Base(tail)
		isEditable = fileType.Ext == ".md" || ((name == "post.html" || name == "postlist.html") && !strings.Contains(parent, "/"))
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		switch next {
		case "":
			isEditable = fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md"
		case "posts":
			isEditable = false
		case "themes":
			isEditable = fileType.Ext == ".html" || fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md" || fileType.Ext == ".txt"
		default:
			isEditable = fileType.Ext == ".css" || fileType.Ext == ".js" || fileType.Ext == ".md"
		}
		if fileType.Ext == ".html" && !isEditable {
			fileType.ContentType = "text/plain; charset=utf-8"
		}
	default:
		nbrew.notFound(w, r)
		return
	}

	switch r.Method {
	case "GET", "HEAD":
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
		if fileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
			response.FileID = fileInfo.FileID
			response.CreationTime = fileInfo.CreationTime
		} else {
			var absolutePath string
			if dirFS, ok := nbrew.FS.(*DirFS); ok {
				absolutePath = path.Join(dirFS.RootDir, response.SitePrefix, response.FilePath)
			}
			response.CreationTime = CreationTime(absolutePath, fileInfo)
		}
		response.FilePath = filePath
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		response.Size = fileInfo.Size()
		response.ImgDomain = nbrew.ImgDomain
		_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)

		if isEditable {
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			response.Content = b.String()
		}

		switch head {
		case "pages":
			if tail == "index.html" {
				response.URL = template.URL(response.ContentBaseURL)
				response.AssetDir = "output"
			} else {
				response.URL = template.URL(response.ContentBaseURL + "/" + strings.TrimSuffix(tail, ".html") + "/")
				response.AssetDir = path.Join("output", strings.TrimSuffix(tail, ".html"))
			}
			if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
				group, groupctx := errgroup.WithContext(r.Context())
				group.Go(func() error {
					pinnedAssets, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM pinned_file" +
							" JOIN files ON files.file_id = pinned_file.file_id" +
							" WHERE pinned_file.parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
							" AND NOT files.is_dir" +
							" AND (" +
							"files.file_path LIKE '%.jpeg'" +
							" OR files.file_path LIKE '%.jpg'" +
							" OR files.file_path LIKE '%.png'" +
							" OR files.file_path LIKE '%.webp'" +
							" OR files.file_path LIKE '%.gif'" +
							" OR files.file_path LIKE '%.css'" +
							" OR files.file_path LIKE '%.js'" +
							" OR files.file_path LIKE '%.md'" +
							") " +
							" ORDER BY files.file_path",
						Values: []any{
							sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
						},
					}, func(row *sq.Row) Asset {
						filePath := row.String("files.file_path")
						return Asset{
							FileID:       row.UUID("files.file_id"),
							Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
							Name:         path.Base(filePath),
							Size:         row.Int64("files.size"),
							ModTime:      row.Time("files.mod_time"),
							CreationTime: row.Time("files.creation_time"),
							Content:      strings.TrimSpace(row.String("text")),
						}
					})
					if err != nil {
						return err
					}
					response.PinnedAssets = pinnedAssets
					for i := range response.PinnedAssets {
						asset := &response.PinnedAssets[i]
						if strings.HasPrefix(asset.Content, "!alt ") {
							altText, _, _ := strings.Cut(asset.Content, "\n")
							asset.AltText = strings.TrimSpace(strings.TrimPrefix(altText, "!alt "))
						}
					}
					return nil
				})
				group.Go(func() error {
					assets, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM files" +
							" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
							" AND NOT is_dir" +
							" AND (" +
							"file_path LIKE '%.jpeg'" +
							" OR file_path LIKE '%.jpg'" +
							" OR file_path LIKE '%.png'" +
							" OR file_path LIKE '%.webp'" +
							" OR file_path LIKE '%.gif'" +
							" OR file_path LIKE '%.css'" +
							" OR file_path LIKE '%.js'" +
							" OR file_path LIKE '%.md'" +
							") " +
							" ORDER BY file_path",
						Values: []any{
							sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
						},
					}, func(row *sq.Row) Asset {
						return Asset{
							FileID:       row.UUID("file_id"),
							Parent:       response.AssetDir,
							Name:         path.Base(row.String("file_path")),
							Size:         row.Int64("size"),
							ModTime:      row.Time("mod_time"),
							CreationTime: row.Time("creation_time"),
							Content:      strings.TrimSpace(row.String("text")),
						}
					})
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						return err
					}
					response.Assets = assets
					for i := range response.Assets {
						asset := &response.Assets[i]
						if strings.HasPrefix(asset.Content, "!alt ") {
							altText, _, _ := strings.Cut(asset.Content, "\n")
							asset.AltText = strings.TrimSpace(strings.TrimPrefix(altText, "!alt "))
						}
					}
					return nil
				})
				err := group.Wait()
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			} else {
				dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				for _, dirEntry := range dirEntries {
					if dirEntry.IsDir() {
						continue
					}
					name := dirEntry.Name()
					switch path.Ext(name) {
					case ".jpeg", ".jpg", ".png", ".webp", "gif", ".css", ".js", ".md":
						fileInfo, err := dirEntry.Info()
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							nbrew.internalServerError(w, r, err)
							return
						}
						var absolutePath string
						if dirFS, ok := nbrew.FS.(*DirFS); ok {
							absolutePath = path.Join(dirFS.RootDir, sitePrefix, response.AssetDir, name)
						}
						response.Assets = append(response.Assets, Asset{
							Parent:       response.AssetDir,
							Name:         name,
							Size:         fileInfo.Size(),
							ModTime:      fileInfo.ModTime(),
							CreationTime: CreationTime(absolutePath, fileInfo),
						})
					}
				}
			}
		case "posts":
			response.URL = template.URL(response.ContentBaseURL + "/" + strings.TrimSuffix(filePath, ".md") + "/")
			response.AssetDir = path.Join("output", strings.TrimSuffix(filePath, ".md"))
			if databaseFS, ok := nbrew.FS.(*DatabaseFS); ok {
				group, groupctx := errgroup.WithContext(r.Context())
				group.Go(func() error {
					pinnedAssets, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM pinned_file" +
							" JOIN files ON files.file_id = pinned_file.file_id" +
							" WHERE pinned_file.parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
							" AND NOT files.is_dir" +
							" AND (" +
							"files.file_path LIKE '%.jpeg'" +
							" OR files.file_path LIKE '%.jpg'" +
							" OR files.file_path LIKE '%.png'" +
							" OR files.file_path LIKE '%.webp'" +
							" OR files.file_path LIKE '%.gif'" +
							") " +
							" ORDER BY files.file_path",
						Values: []any{
							sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
						},
					}, func(row *sq.Row) Asset {
						filePath := row.String("files.file_path")
						return Asset{
							FileID:       row.UUID("files.file_id"),
							Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
							Name:         path.Base(filePath),
							Size:         row.Int64("files.size"),
							ModTime:      row.Time("files.mod_time"),
							CreationTime: row.Time("files.creation_time"),
							Content:      strings.TrimSpace(row.String("text")),
						}
					})
					if err != nil {
						return err
					}
					response.PinnedAssets = pinnedAssets
					for i := range response.PinnedAssets {
						asset := &response.PinnedAssets[i]
						if strings.HasPrefix(asset.Content, "!alt ") {
							altText, _, _ := strings.Cut(asset.Content, "\n")
							asset.AltText = strings.TrimSpace(strings.TrimPrefix(altText, "!alt "))
						}
					}
					return nil
				})
				group.Go(func() error {
					assets, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "SELECT {*}" +
							" FROM files" +
							" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {assetDir})" +
							" AND NOT is_dir" +
							" AND (" +
							"file_path LIKE '%.jpeg'" +
							" OR file_path LIKE '%.jpg'" +
							" OR file_path LIKE '%.png'" +
							" OR file_path LIKE '%.webp'" +
							" OR file_path LIKE '%.gif'" +
							") " +
							" ORDER BY file_path",
						Values: []any{
							sq.StringParam("assetDir", path.Join(sitePrefix, response.AssetDir)),
						},
					}, func(row *sq.Row) Asset {
						return Asset{
							FileID:       row.UUID("file_id"),
							Parent:       response.AssetDir,
							Name:         path.Base(row.String("file_path")),
							Size:         row.Int64("size"),
							ModTime:      row.Time("mod_time"),
							CreationTime: row.Time("creation_time"),
							Content:      strings.TrimSpace(row.String("text")),
						}
					})
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						return err
					}
					response.Assets = assets
					for i := range response.Assets {
						asset := &response.Assets[i]
						if strings.HasPrefix(asset.Content, "!alt ") {
							altText, _, _ := strings.Cut(asset.Content, "\n")
							asset.AltText = strings.TrimSpace(strings.TrimPrefix(altText, "!alt "))
						}
					}
					return nil
				})
				err := group.Wait()
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			} else {
				dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, response.AssetDir))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				for _, dirEntry := range dirEntries {
					if dirEntry.IsDir() {
						continue
					}
					name := dirEntry.Name()
					switch path.Ext(name) {
					case ".jpeg", ".jpg", ".png", ".webp", "gif":
						fileInfo, err := dirEntry.Info()
						if err != nil {
							getLogger(r.Context()).Error(err.Error())
							nbrew.internalServerError(w, r, err)
							return
						}
						var absolutePath string
						if dirFS, ok := nbrew.FS.(*DirFS); ok {
							absolutePath = path.Join(dirFS.RootDir, sitePrefix, response.AssetDir, name)
						}
						response.Assets = append(response.Assets, Asset{
							Name:         name,
							Parent:       response.AssetDir,
							Size:         fileInfo.Size(),
							ModTime:      fileInfo.ModTime(),
							CreationTime: CreationTime(absolutePath, fileInfo),
						})
					}
				}
			}
		case "output":
			if isEditable {
				next, _, _ := strings.Cut(tail, "/")
				if next != "posts" && next != "themes" {
					dir := path.Dir(tail)
					if dir == "." {
						response.BelongsTo = "pages/index.html"
					} else {
						response.BelongsTo = path.Join("pages", dir+".html")
					}
				}
			}
		}

		if response.PinnedAssets == nil {
			response.PinnedAssets = []Asset{}
		}
		if response.Assets == nil {
			response.Assets = []Asset{}
		}
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

		if !isEditable {
			serveFile(w, r, path.Base(filePath), fileInfo.Size(), fileType, file, "no-cache")
			return
		}

		referer := nbrew.getReferer(r)
		clipboard := make(url.Values)
		isInClipboard := make(map[string]bool)
		cookie, _ := r.Cookie("clipboard")
		if cookie != nil {
			values, err := url.ParseQuery(cookie.Value)
			if err == nil && values.Get("sitePrefix") == sitePrefix {
				if values.Has("cut") {
					clipboard.Set("cut", "")
				}
				clipboard.Set("sitePrefix", values.Get("sitePrefix"))
				clipboard.Set("parent", values.Get("parent"))
				for _, name := range values["name"] {
					if isInClipboard[name] {
						continue
					}
					clipboard.Add("name", name)
					isInClipboard[name] = true
				}
			}
		}
		funcMap := map[string]any{
			"join":                  path.Join,
			"dir":                   path.Dir,
			"base":                  path.Base,
			"ext":                   path.Ext,
			"hasPrefix":             strings.HasPrefix,
			"hasSuffix":             strings.HasSuffix,
			"trimPrefix":            strings.TrimPrefix,
			"trimSuffix":            strings.TrimSuffix,
			"humanReadableFileSize": humanReadableFileSize,
			"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
			"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
			"referer":               func() string { return referer },
			"clipboard":             func() url.Values { return clipboard },
			"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
			"isInClipboard": func(name string) bool {
				if sitePrefix != clipboard.Get("sitePrefix") {
					return false
				}
				if response.AssetDir != clipboard.Get("parent") {
					return false
				}
				return isInClipboard[name]
			},
		}
		tmpl, err := template.New("file.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/file.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.executeTemplate(w, r, tmpl, &response)
	case "POST":
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
					"from": "file",
				},
				"regenerationStats": response.RegenerationStats,
				"uploadCount":       response.UploadCount,
				"uploadSize":        response.UploadSize,
				"filesExist":        response.FilesExist,
				"filesTooBig":       response.FilesTooBig,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, urlReplacer.Replace("/"+path.Join("files", sitePrefix, filePath)), http.StatusFound)
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

		if !isEditable {
			nbrew.methodNotAllowed(w, r)
			return
		}

		var request struct {
			Content string
		}
		var err error
		var reader *multipart.Reader
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&request)
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
			request.Content = r.Form.Get("content")
		case "multipart/form-data":
			reader, err = r.MultipartReader()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			part, err := reader.NextPart()
			if err != nil {
				if err == io.EOF {
					break
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			var maxBytesErr *http.MaxBytesError
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
			if formName == "content" {
				request.Content = b.String()
			}
		default:
			nbrew.unsupportedContentType(w, r)
			return
		}

		response := Response{
			ContentBaseURL: nbrew.contentBaseURL(sitePrefix),
			SitePrefix:     sitePrefix,
			FilePath:       filePath,
			IsDir:          fileInfo.IsDir(),
			ModTime:        fileInfo.ModTime(),
			Content:        request.Content,
		}
		if fileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
			response.CreationTime = fileInfo.CreationTime
		} else {
			var absolutePath string
			if dirFS, ok := nbrew.FS.(*DirFS); ok {
				absolutePath = path.Join(dirFS.RootDir, sitePrefix, response.FilePath)
			}
			response.CreationTime = CreationTime(absolutePath, fileInfo)
		}

		writer, err := nbrew.FS.OpenWriter(path.Join(sitePrefix, filePath), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.Copy(writer, strings.NewReader(response.Content))
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

		var numUploadedImages atomic.Int64
		head, tail, _ := strings.Cut(filePath, "/")
		if (head == "pages" || head == "posts") && contentType == "multipart/form-data" {
			var outputDir string
			if head == "posts" {
				outputDir = path.Join(sitePrefix, "output/posts", strings.TrimSuffix(tail, ".md"))
			} else {
				if filePath == "pages/index.html" {
					outputDir = path.Join(sitePrefix, "output")
				} else {
					outputDir = path.Join(sitePrefix, "output", strings.TrimSuffix(tail, ".html"))
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
			var monotonicCounter atomic.Int64
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
					monotonicCounter.CompareAndSwap(0, now.Unix())
					binary.BigEndian.PutUint64(timestamp[:], uint64(max(now.Unix(), monotonicCounter.Add(1))))
					timestampSuffix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
					fileName = "image-" + timestampSuffix + ext
				}
				filePath := path.Join(outputDir, fileName)
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
						numUploadedImages.Add(1)
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
			err = siteGen.GeneratePage(r.Context(), filePath, response.Content)
			response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
			if err != nil {
				if !errors.As(err, &response.RegenerationStats.TemplateError) {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			}
			response.RegenerationStats.Count = 1
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
			category := path.Dir(tail)
			if category == "." {
				category = ""
			}
			name := path.Base(tail)
			if name == "post.html" {
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
				response.RegenerationStats.Count, err = siteGen.GeneratePosts(r.Context(), category, tmpl)
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			} else if name == "postlist.html" {
				startedAt := time.Now()
				tmpl, err := siteGen.PostListTemplate(r.Context(), category)
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				response.RegenerationStats.Count, err = siteGen.GeneratePostList(r.Context(), category, tmpl)
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			} else if strings.HasSuffix(name, ".md") {
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
				err = siteGen.GeneratePost(r.Context(), filePath, response.Content, response.CreationTime, tmpl)
				response.RegenerationStats.Count = 1
				response.RegenerationStats.TimeTaken = time.Since(startedAt).String()
				if err != nil {
					if errors.As(err, &response.RegenerationStats.TemplateError) {
						writeResponse(w, r, response)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
			}
		case "output":
			next, _, _ := strings.Cut(tail, "/")
			if next != "posts" && next != "themes" && fileType.Ext == ".md" {
				var parentPage string
				if tail == "" {
					parentPage = "pages/index.html"
				} else {
					parentPage = path.Join("pages", path.Dir(tail)+".html")
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
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
