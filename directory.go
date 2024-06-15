package nb10

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) directory(w http.ResponseWriter, r *http.Request, user User, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type File struct {
		FileID       ID        `json:"fileID"`
		Parent       string    `json:"parent"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
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
		PinnedFiles       []File            `json:"pinnedFiles"`
		Files             []File            `json:"files"`
		Sort              string            `json:"sort"`
		Order             string            `json:"order"`
		From              string            `json:"from"`
		FromCreated       string            `json:"fromCreated"`
		FromEdited        string            `json:"fromEdited"`
		FromTime          string            `json:"fromTime"`
		Before            string            `json:"before"`
		BeforeCreated     string            `json:"beforeCreated"`
		BeforeEdited      string            `json:"beforeEdited"`
		BeforeTime        string            `json:"beforeTime"`
		Limit             int               `json:"limit"`
		PreviousURL       string            `json:"previousURL"`
		NextURL           string            `json:"nextURL"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if response.PinnedFiles == nil {
			response.PinnedFiles = []File{}
		}
		if response.Files == nil {
			response.Files = []File{}
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
			"float64ToInt64":        func(n float64) int64 { return int64(n) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
			"generateBreadcrumbLinks": func(sitePrefix, filePath string) template.HTML {
				var b strings.Builder
				b.WriteString("<a href='/files/'>files</a>")
				segments := strings.Split(filePath, "/")
				if sitePrefix != "" {
					segments = append([]string{sitePrefix}, segments...)
				}
				for i := 0; i < len(segments); i++ {
					if segments[i] == "" {
						continue
					}
					href := "/files/" + path.Join(segments[:i+1]...) + "/"
					b.WriteString(" / <a href='" + href + "'>" + segments[i] + "</a>")
				}
				b.WriteString(" /")
				return template.HTML(b.String())
			},
			"isInClipboard": func(name string) bool {
				if sitePrefix != clipboard.Get("sitePrefix") {
					return false
				}
				if response.FilePath != clipboard.Get("parent") {
					return false
				}
				return isInClipboard[name]
			},
		}
		tmpl, err := template.New("directory.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/directory.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.executeTemplate(w, r, tmpl, &response)
	}
	if r.Method != "GET" {
		nbrew.methodNotAllowed(w, r)
		return
	}

	head, _, _ := strings.Cut(filePath, "/")
	if head != "notes" && head != "pages" && head != "posts" && head != "output" {
		nbrew.notFound(w, r)
		return
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
	response.SitePrefix = sitePrefix
	response.UserID = user.UserID
	response.Username = user.Username
	if fileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
		response.FileID = fileInfo.FileID
		response.ModTime = fileInfo.ModTime()
		response.CreationTime = fileInfo.CreationTime
	} else {
		var absolutePath string
		if dirFS, ok := nbrew.FS.(*DirFS); ok {
			absolutePath = path.Join(dirFS.RootDir, response.SitePrefix, response.FilePath)
		}
		response.CreationTime = CreationTime(absolutePath, fileInfo)
	}
	response.FilePath = filePath
	response.IsDir = true
	var sortCookie, orderCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		switch cookie.Name {
		case "sort":
			sortCookie = cookie
		case "order":
			orderCookie = cookie
		}
	}
	response.Sort = strings.ToLower(strings.TrimSpace(r.Form.Get("sort")))
	if response.Sort == "" && sortCookie != nil {
		response.Sort = sortCookie.Value
	}
	switch response.Sort {
	case "name", "edited", "created":
		break
	default:
		if head == "notes" {
			response.Sort = "edited"
		} else if head == "posts" {
			response.Sort = "created"
		} else {
			response.Sort = "name"
		}
	}
	response.Order = strings.ToLower(strings.TrimSpace(r.Form.Get("order")))
	if response.Order == "" && orderCookie != nil {
		response.Order = orderCookie.Value
	}
	switch response.Order {
	case "asc", "desc":
		break
	default:
		if response.Sort == "created" || response.Sort == "edited" {
			response.Order = "desc"
		} else {
			response.Order = "asc"
		}
	}
	if r.Form.Has("persist") {
		if r.Form.Has("sort") {
			isDefaultSort := false
			if head == "notes" {
				isDefaultSort = response.Sort == "edited"
			} else if head == "posts" {
				isDefaultSort = response.Sort == "created"
			} else {
				isDefaultSort = response.Sort == "name"
			}
			if isDefaultSort {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "sort",
					Value:    "0",
					MaxAge:   -1,
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "sort",
					Value:    response.Sort,
					MaxAge:   int((time.Hour * 24 * 365).Seconds()),
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
		if r.Form.Has("order") {
			isDefaultOrder := false
			if response.Sort == "created" || response.Sort == "edited" {
				isDefaultOrder = response.Order == "desc"
			} else {
				isDefaultOrder = response.Order == "asc"
			}
			if isDefaultOrder {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "order",
					Value:    "0",
					MaxAge:   -1,
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "order",
					Value:    response.Order,
					MaxAge:   int((time.Hour * 24 * 365).Seconds()),
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
	}

	databaseFS, ok := nbrew.FS.(*DatabaseFS)
	if !ok {
		dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(path.Join(sitePrefix, filePath))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		response.Files = make([]File, 0, len(dirEntries))
		for _, dirEntry := range dirEntries {
			fileInfo, err := dirEntry.Info()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			name := fileInfo.Name()
			var absolutePath string
			if dirFS, ok := nbrew.FS.(*DirFS); ok {
				absolutePath = path.Join(dirFS.RootDir, sitePrefix, filePath, name)
			}
			file := File{
				Parent:       filePath,
				Name:         name,
				IsDir:        fileInfo.IsDir(),
				Size:         fileInfo.Size(),
				ModTime:      fileInfo.ModTime(),
				CreationTime: CreationTime(absolutePath, fileInfo),
			}
			if file.IsDir {
				response.Files = append(response.Files, file)
				continue
			}
			_, ok := fileTypes[path.Ext(file.Name)]
			if !ok {
				continue
			}
			response.Files = append(response.Files, file)
		}
		switch response.Sort {
		case "name":
			if response.Order == "desc" {
				slices.Reverse(response.Files)
			}
		case "edited":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.ModTime.Equal(b.ModTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.ModTime.Before(b.ModTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		case "created":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.CreationTime.Equal(b.CreationTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.CreationTime.Before(b.CreationTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		}
		writeResponse(w, r, response)
		return
	}

	response.Limit, _ = strconv.Atoi(r.Form.Get("limit"))
	if response.Limit <= 0 {
		response.Limit = 200
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	pinnedFileQuery := sq.Query{
		Dialect: databaseFS.Dialect,
		Format: "SELECT {*}" +
			" FROM pinned_file" +
			" JOIN files ON files.file_id = pinned_file.file_id" +
			" WHERE pinned_file.parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
			" ORDER BY files.file_path",
		Values: []any{
			sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
		},
	}
	pinnedFileMapper := func(row *sq.Row) File {
		filePath := row.String("files.file_path")
		return File{
			FileID:       row.UUID("files.file_id"),
			Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
			Name:         path.Base(filePath),
			Size:         row.Int64("files.size"),
			ModTime:      row.Time("files.mod_time"),
			CreationTime: row.Time("files.creation_time"),
			IsDir:        row.Bool("files.is_dir"),
		}
	}

	const timeFormat = "2006-01-02T150405.999999999Z"
	response.From = r.Form.Get("from")
	fromCreated, _ := time.ParseInLocation(timeFormat, r.Form.Get("fromCreated"), time.UTC)
	if !fromCreated.IsZero() {
		response.FromCreated = fromCreated.Format(timeFormat)
	}
	fromEdited, _ := time.ParseInLocation(timeFormat, r.Form.Get("fromEdited"), time.UTC)
	if !fromEdited.IsZero() {
		response.FromEdited = fromEdited.Format(timeFormat)
	}
	response.Before = r.Form.Get("before")
	beforeCreated, _ := time.ParseInLocation(timeFormat, r.Form.Get("beforeCreated"), time.UTC)
	if !beforeCreated.IsZero() {
		response.BeforeCreated = beforeCreated.Format(timeFormat)
	}
	beforeEdited, _ := time.ParseInLocation(timeFormat, r.Form.Get("beforeEdited"), time.UTC)
	if !beforeEdited.IsZero() {
		response.BeforeEdited = beforeEdited.Format(timeFormat)
	}

	if response.Sort == "name" {
		if response.From != "" {
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				pinnedFiles, err := sq.FetchAll(groupctx, databaseFS.DB, pinnedFileQuery, pinnedFileMapper)
				if err != nil {
					return err
				}
				response.PinnedFiles = pinnedFiles
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Order == "asc" {
					filter = sq.Expr("file_path >= {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path ASC")
				} else {
					filter = sq.Expr("file_path <= {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path DESC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&limit=" + strconv.Itoa(response.Limit),
					}
					response.NextURL = uri.String()
				}
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Order == "asc" {
					filter = sq.Expr("file_path < {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path DESC")
				} else {
					filter = sq.Expr("file_path > {}", path.Join(sitePrefix, filePath, response.From))
					order = sq.Expr("file_path ASC")
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return err
				}
				if hasPreviousFile {
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&before=" + url.QueryEscape(response.From) +
							"&limit=" + strconv.Itoa(response.Limit),
					}
					response.PreviousURL = uri.String()
				}
				return nil
			})
			err := group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			writeResponse(w, r, response)
			return
		}
		response.Before = r.Form.Get("before")
		if response.Before != "" {
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				pinnedFiles, err := sq.FetchAll(groupctx, databaseFS.DB, pinnedFileQuery, pinnedFileMapper)
				if err != nil {
					return err
				}
				response.PinnedFiles = pinnedFiles
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Order == "asc" {
					filter = sq.Expr("file_path < {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path DESC")
				} else {
					filter = sq.Expr("file_path > {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path ASC")
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					response.Files = response.Files[:len(response.Files)-1]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
						RawQuery: "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&before=" + url.QueryEscape(response.Files[len(response.Files)-1].Name) +
							"&limit=" + strconv.Itoa(response.Limit),
					}
					response.PreviousURL = uri.String()
				}
				slices.Reverse(response.Files)
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Order == "asc" {
					filter = sq.Expr("file_path >= {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path ASC")
				} else {
					filter = sq.Expr("file_path <= {}", path.Join(sitePrefix, filePath, response.Before))
					order = sq.Expr("file_path DESC")
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return err
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
					RawQuery: "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&limit=" + strconv.Itoa(response.Limit),
				}
				response.NextURL = uri.String()
				return nil
			})
			err := group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			writeResponse(w, r, response)
			return
		}
	}

	if response.Sort == "edited" || response.Sort == "created" {
		fromTime, _ := time.ParseInLocation(timeFormat, r.Form.Get("fromTime"), time.UTC)
		from := r.Form.Get("from")
		if !fromTime.IsZero() && from != "" {
			response.FromTime = fromTime.Format(timeFormat)
			response.From = from
			timeParam := sq.TimeParam("timeParam", fromTime)
			pathParam := sq.StringParam("pathParam", path.Join(response.SitePrefix, response.FilePath, response.From))
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				pinnedFiles, err := sq.FetchAll(groupctx, databaseFS.DB, pinnedFileQuery, pinnedFileMapper)
				if err != nil {
					return err
				}
				response.PinnedFiles = pinnedFiles
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Sort == "edited" {
					if response.Order == "asc" {
						filter = sq.Expr("(mod_time, file_path) >= ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("mod_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("(mod_time, file_path) <= ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("mod_time DESC, file_path DESC")
					}
				} else if response.Sort == "created" {
					if response.Order == "asc" {
						filter = sq.Expr("(creation_time, file_path) >= ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("creation_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("(creation_time, file_path) <= ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("creation_time DESC, file_path DESC")
					}
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					nextFile := response.Files[response.Limit]
					response.Files = response.Files[:response.Limit]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
					}
					if response.Sort == "edited" {
						uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&fromTime=" + url.QueryEscape(nextFile.ModTime.UTC().Format(timeFormat)) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&limit=" + strconv.Itoa(response.Limit)
					} else if response.Sort == "created" {
						uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&fromTime=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(timeFormat)) +
							"&from=" + url.QueryEscape(nextFile.Name) +
							"&limit=" + strconv.Itoa(response.Limit)
					}
					response.NextURL = uri.String()
				}
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Sort == "edited" {
					if response.Order == "asc" {
						filter = sq.Expr("(mod_time, file_path) < ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("mod_time DESC, file_path DESC")
					} else {
						filter = sq.Expr("(mod_time, file_path) > ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("mod_time ASC, file_path ASC")
					}
				} else if response.Sort == "created" {
					if response.Order == "asc" {
						filter = sq.Expr("(creation_time, file_path) < ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("creation_time DESC, file_path DESC")
					} else {
						filter = sq.Expr("(creation_time, file_path) > ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("creation_time ASC, file_path ASC")
					}
				}
				hasPreviousFile, err := sq.FetchExists(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT 1" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
					},
				})
				if err != nil {
					return err
				}
				if hasPreviousFile {
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
					}
					if response.From != "" {
						uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&beforeTime=" + url.QueryEscape(response.FromTime) +
							"&before=" + url.QueryEscape(response.From) +
							"&limit=" + strconv.Itoa(response.Limit)
					} else {
						uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&beforeTime=" + url.QueryEscape(response.FromTime) +
							"&before=" + url.QueryEscape(response.From) +
							"&limit=" + strconv.Itoa(response.Limit)
					}
					response.PreviousURL = uri.String()
				}
				return nil
			})
			err := group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			writeResponse(w, r, response)
			return
		}
		beforeTime, _ := time.ParseInLocation(timeFormat, r.Form.Get("beforeTime"), time.UTC)
		before := r.Form.Get("before")
		if !beforeTime.IsZero() && before != "" {
			response.BeforeTime = beforeTime.Format(timeFormat)
			response.Before = before
			timeParam := sq.TimeParam("timeParam", beforeTime)
			pathParam := sq.StringParam("pathParam", path.Join(response.SitePrefix, response.FilePath, response.Before))
			group, groupctx := errgroup.WithContext(r.Context())
			group.Go(func() error {
				pinnedFiles, err := sq.FetchAll(groupctx, databaseFS.DB, pinnedFileQuery, pinnedFileMapper)
				if err != nil {
					return err
				}
				response.PinnedFiles = pinnedFiles
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Sort == "edited" {
					if response.Order == "asc" {
						filter = sq.Expr("(mod_time, file_path) < ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("mod_time DESC, file_path DESC")
					} else {
						filter = sq.Expr("(mod_time, file_path) > ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("mod_time ASC, file_path ASC")
					}
				} else if response.Sort == "created" {
					if response.Order == "asc" {
						filter = sq.Expr("(creation_time, file_path) < ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("creation_time DESC, file_path DESC")
					} else {
						filter = sq.Expr("(creation_time, file_path) > ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("creation_time ASC, file_path ASC")
					}
				}
				files, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT {limit} + 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
						sq.IntParam("limit", response.Limit),
					},
				}, func(row *sq.Row) File {
					filePath := row.String("files.file_path")
					return File{
						FileID:       row.UUID("files.file_id"),
						Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
						Name:         path.Base(filePath),
						Size:         row.Int64("files.size"),
						ModTime:      row.Time("files.mod_time"),
						CreationTime: row.Time("files.creation_time"),
						IsDir:        row.Bool("files.is_dir"),
					}
				})
				if err != nil {
					return err
				}
				response.Files = files
				if len(response.Files) > response.Limit {
					response.Files = response.Files[:len(response.Files)-1]
					uri := &url.URL{
						Scheme: scheme,
						Host:   r.Host,
						Path:   r.URL.Path,
					}
					if response.Sort == "edited" {
						uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&beforeTime=" + url.QueryEscape(response.Files[len(response.Files)-1].ModTime.UTC().Format(timeFormat)) +
							"&before=" + url.QueryEscape(response.Files[len(response.Files)-1].Name) +
							"&limit=" + strconv.Itoa(response.Limit)
					} else if response.Sort == "created" {
						uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
							"&order=" + url.QueryEscape(response.Order) +
							"&beforeTime=" + url.QueryEscape(response.Files[len(response.Files)-1].CreationTime.UTC().Format(timeFormat)) +
							"&before=" + url.QueryEscape(response.Files[len(response.Files)-1].Name) +
							"&limit=" + strconv.Itoa(response.Limit)
					}
					response.PreviousURL = uri.String()
				}
				slices.Reverse(response.Files)
				return nil
			})
			group.Go(func() error {
				var filter, order sq.Expression
				if response.Sort == "edited" {
					if response.Order == "asc" {
						filter = sq.Expr("(mod_time, file_path) >= ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("mod_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("(mod_time, file_path) <= ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("mod_time DESC, file_path DESC")
					}
				} else if response.Sort == "created" {
					if response.Order == "asc" {
						filter = sq.Expr("(creation_time, file_path) >= ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("creation_time ASC, file_path ASC")
					} else {
						filter = sq.Expr("(creation_time, file_path) <= ({timeParam}, {pathParam})", timeParam, pathParam)
						order = sq.Expr("creation_time DESC, file_path DESC")
					}
				}
				nextFile, err := sq.FetchOne(groupctx, databaseFS.DB, sq.Query{
					Dialect: databaseFS.Dialect,
					Format: "SELECT {*}" +
						" FROM files" +
						" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
						" AND {filter}" +
						" ORDER BY {order}" +
						" LIMIT 1",
					Values: []any{
						sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
						sq.Param("filter", filter),
						sq.Param("order", order),
					},
				}, func(row *sq.Row) File {
					return File{
						Name:         path.Base(row.String("file_path")),
						ModTime:      row.Time("mod_time"),
						CreationTime: row.Time("creation_time"),
					}
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return nil
					}
					return err
				}
				uri := &url.URL{
					Scheme: scheme,
					Host:   r.Host,
					Path:   r.URL.Path,
				}
				if response.Sort == "edited" {
					uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&fromTime=" + url.QueryEscape(nextFile.ModTime.UTC().Format(timeFormat)) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&limit=" + strconv.Itoa(response.Limit)
				} else if response.Sort == "created" {
					uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
						"&order=" + url.QueryEscape(response.Order) +
						"&fromTime=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(timeFormat)) +
						"&from=" + url.QueryEscape(nextFile.Name) +
						"&limit=" + strconv.Itoa(response.Limit)
				}
				response.NextURL = uri.String()
				return nil
			})
			err := group.Wait()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			writeResponse(w, r, response)
			return
		}
	}

	group, groupctx := errgroup.WithContext(r.Context())
	group.Go(func() error {
		pinnedFiles, err := sq.FetchAll(groupctx, databaseFS.DB, pinnedFileQuery, pinnedFileMapper)
		if err != nil {
			return err
		}
		response.PinnedFiles = pinnedFiles
		return nil
	})
	group.Go(func() error {
		var order sq.Expression
		if response.Sort == "name" {
			if response.Order == "asc" {
				order = sq.Expr("file_path ASC")
			} else {
				order = sq.Expr("file_path DESC")
			}
		} else if response.Sort == "edited" {
			if response.Order == "asc" {
				order = sq.Expr("mod_time ASC, file_path ASC")
			} else {
				order = sq.Expr("mod_time DESC, file_path DESC")
			}
		} else if response.Sort == "created" {
			if response.Order == "asc" {
				order = sq.Expr("creation_time ASC, file_path ASC")
			} else {
				order = sq.Expr("creation_time DESC, file_path DESC")
			}
		}
		files, err := sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
				" ORDER BY {order}" +
				" LIMIT {limit} + 1",
			Values: []any{
				sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
				sq.Param("order", order),
				sq.IntParam("limit", response.Limit),
			},
		}, func(row *sq.Row) File {
			filePath := row.String("files.file_path")
			return File{
				FileID:       row.UUID("files.file_id"),
				Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
				Name:         path.Base(filePath),
				Size:         row.Int64("files.size"),
				ModTime:      row.Time("files.mod_time"),
				CreationTime: row.Time("files.creation_time"),
				IsDir:        row.Bool("files.is_dir"),
			}
		})
		if err != nil {
			return err
		}
		response.Files = files
		if len(response.Files) > response.Limit {
			nextFile := response.Files[response.Limit]
			response.Files = response.Files[:response.Limit]
			uri := &url.URL{
				Scheme: scheme,
				Host:   r.Host,
				Path:   r.URL.Path,
			}
			if response.Sort == "name" {
				uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
					"&order=" + url.QueryEscape(response.Order) +
					"&from=" + url.QueryEscape(nextFile.Name) +
					"&limit=" + strconv.Itoa(response.Limit)
			} else if response.Sort == "edited" {
				uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
					"&order=" + url.QueryEscape(response.Order) +
					"&fromTime=" + url.QueryEscape(nextFile.ModTime.UTC().Format(timeFormat)) +
					"&from=" + url.QueryEscape(nextFile.Name) +
					"&limit=" + strconv.Itoa(response.Limit)
			} else if response.Sort == "created" {
				uri.RawQuery = "sort=" + url.QueryEscape(response.Sort) +
					"&order=" + url.QueryEscape(response.Order) +
					"&fromTime=" + url.QueryEscape(nextFile.CreationTime.UTC().Format(timeFormat)) +
					"&from=" + url.QueryEscape(nextFile.Name) +
					"&limit=" + strconv.Itoa(response.Limit)
			}
			response.NextURL = uri.String()
		}
		return nil
	})
	err = group.Wait()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	writeResponse(w, r, response)
	return
}

var timeFormats = []string{
	"2006-01-02T15:04:05.999999999-07:00",
	"2006-01-02",
}

func (nbrew *Notebrew) directoryV2(w http.ResponseWriter, r *http.Request, user User, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type File struct {
		FileID       ID        `json:"fileID"`
		Parent       string    `json:"parent"`
		Name         string    `json:"name"`
		IsDir        bool      `json:"isDir"`
		ModTime      time.Time `json:"modTime"`
		CreationTime time.Time `json:"creationTime"`
		Size         int64     `json:"size"`
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
		PinnedFiles       []File            `json:"pinnedFiles"`
		Files             []File            `json:"files"`
		Sort              string            `json:"sort"`
		Order             string            `json:"order"`
		From              string            `json:"from"`
		FromCreated       string            `json:"fromCreated"`
		FromEdited        string            `json:"fromEdited"`
		FromTime          string            `json:"fromTime"`
		Before            string            `json:"before"`
		BeforeCreated     string            `json:"beforeCreated"`
		BeforeEdited      string            `json:"beforeEdited"`
		BeforeTime        string            `json:"beforeTime"`
		Limit             int               `json:"limit"`
		PreviousURL       string            `json:"previousURL"`
		NextURL           string            `json:"nextURL"`
		RegenerationStats RegenerationStats `json:"regenerationStats"`
		PostRedirectGet   map[string]any    `json:"postRedirectGet"`
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if response.PinnedFiles == nil {
			response.PinnedFiles = []File{}
		}
		if response.Files == nil {
			response.Files = []File{}
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
		referer := nbrew.getReferer(r)
		clipboard := make(url.Values)
		isInClipboard := make(map[string]bool)
		cookie, _ := r.Cookie("clipboard")
		if cookie != nil {
			values, err := url.ParseQuery(cookie.Value)
			if err == nil {
				sourceSitePrefix := values.Get("sitePrefix")
				if sourceSitePrefix == sitePrefix {
					if values.Has("cut") {
						clipboard.Set("cut", "")
					}
					clipboard.Set("sitePrefix", sourceSitePrefix)
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
			"float64ToInt64":        func(n float64) int64 { return int64(n) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
			"generateBreadcrumbLinks": func(sitePrefix, filePath string) template.HTML {
				var b strings.Builder
				b.WriteString("<a href='/files/'>files</a>")
				segments := strings.Split(filePath, "/")
				if sitePrefix != "" {
					segments = append([]string{sitePrefix}, segments...)
				}
				for i := 0; i < len(segments); i++ {
					if segments[i] == "" {
						continue
					}
					href := "/files/" + path.Join(segments[:i+1]...) + "/"
					b.WriteString(" / <a href='" + href + "'>" + segments[i] + "</a>")
				}
				b.WriteString(" /")
				return template.HTML(b.String())
			},
			"isInClipboard": func(name string) bool {
				if sitePrefix != clipboard.Get("sitePrefix") {
					return false
				}
				if response.FilePath != clipboard.Get("parent") {
					return false
				}
				return isInClipboard[name]
			},
		}
		tmpl, err := template.New("directory.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/directory.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.executeTemplate(w, r, tmpl, &response)
	}
	if r.Method != "GET" {
		nbrew.methodNotAllowed(w, r)
		return
	}

	head, _, _ := strings.Cut(filePath, "/")
	if head != "notes" && head != "pages" && head != "posts" && head != "output" {
		nbrew.notFound(w, r)
		return
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
	response.SitePrefix = sitePrefix
	response.UserID = user.UserID
	response.Username = user.Username
	if fileInfo, ok := fileInfo.(*DatabaseFileInfo); ok {
		response.FileID = fileInfo.FileID
		response.ModTime = fileInfo.ModTime()
		response.CreationTime = fileInfo.CreationTime
	} else {
		var absolutePath string
		if dirFS, ok := nbrew.FS.(*DirFS); ok {
			absolutePath = path.Join(dirFS.RootDir, response.SitePrefix, response.FilePath)
		}
		response.CreationTime = CreationTime(absolutePath, fileInfo)
	}
	response.FilePath = filePath
	response.IsDir = true
	var sortCookie, orderCookie *http.Cookie
	for _, cookie := range r.Cookies() {
		switch cookie.Name {
		case "sort":
			sortCookie = cookie
		case "order":
			orderCookie = cookie
		}
	}
	response.Sort = strings.ToLower(strings.TrimSpace(r.Form.Get("sort")))
	if response.Sort == "" && sortCookie != nil {
		response.Sort = sortCookie.Value
	}
	switch response.Sort {
	case "name", "edited", "created":
		break
	default:
		if head == "notes" {
			response.Sort = "edited"
		} else if head == "posts" {
			response.Sort = "created"
		} else {
			response.Sort = "name"
		}
	}
	response.Order = strings.ToLower(strings.TrimSpace(r.Form.Get("order")))
	if response.Order == "" && orderCookie != nil {
		response.Order = orderCookie.Value
	}
	switch response.Order {
	case "asc", "desc":
		break
	default:
		if response.Sort == "created" || response.Sort == "edited" {
			response.Order = "desc"
		} else {
			response.Order = "asc"
		}
	}
	if r.Form.Has("persist") {
		if r.Form.Has("sort") {
			isDefaultSort := false
			if head == "notes" {
				isDefaultSort = response.Sort == "edited"
			} else if head == "posts" {
				isDefaultSort = response.Sort == "created"
			} else {
				isDefaultSort = response.Sort == "name"
			}
			if isDefaultSort {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "sort",
					Value:    "0",
					MaxAge:   -1,
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "sort",
					Value:    response.Sort,
					MaxAge:   int((time.Hour * 24 * 365).Seconds()),
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
		if r.Form.Has("order") {
			isDefaultOrder := false
			if response.Sort == "created" || response.Sort == "edited" {
				isDefaultOrder = response.Order == "desc"
			} else {
				isDefaultOrder = response.Order == "asc"
			}
			if isDefaultOrder {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "order",
					Value:    "0",
					MaxAge:   -1,
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			} else {
				http.SetCookie(w, &http.Cookie{
					Path:     r.URL.EscapedPath(),
					Name:     "order",
					Value:    response.Order,
					MaxAge:   int((time.Hour * 24 * 365).Seconds()),
					Secure:   r.TLS != nil,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
	}

	databaseFS, ok := nbrew.FS.(*DatabaseFS)
	_ = databaseFS
	if !ok {
		dirEntries, err := nbrew.FS.WithContext(r.Context()).ReadDir(path.Join(sitePrefix, filePath))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		response.Files = make([]File, 0, len(dirEntries))
		for _, dirEntry := range dirEntries {
			fileInfo, err := dirEntry.Info()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			name := fileInfo.Name()
			var absolutePath string
			if dirFS, ok := nbrew.FS.(*DirFS); ok {
				absolutePath = path.Join(dirFS.RootDir, sitePrefix, filePath, name)
			}
			file := File{
				Parent:       filePath,
				Name:         name,
				IsDir:        fileInfo.IsDir(),
				Size:         fileInfo.Size(),
				ModTime:      fileInfo.ModTime(),
				CreationTime: CreationTime(absolutePath, fileInfo),
			}
			if file.IsDir {
				response.Files = append(response.Files, file)
				continue
			}
			_, ok := fileTypes[path.Ext(file.Name)]
			if !ok {
				continue
			}
			response.Files = append(response.Files, file)
		}
		switch response.Sort {
		case "name":
			if response.Order == "desc" {
				slices.Reverse(response.Files)
			}
		case "edited":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.ModTime.Equal(b.ModTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.ModTime.Before(b.ModTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		case "created":
			slices.SortFunc(response.Files, func(a, b File) int {
				if a.CreationTime.Equal(b.CreationTime) {
					return strings.Compare(a.Name, b.Name)
				}
				if a.CreationTime.Before(b.CreationTime) {
					if response.Order == "asc" {
						return -1
					} else {
						return 1
					}
				} else {
					if response.Order == "asc" {
						return 1
					} else {
						return -1
					}
				}
			})
		}
		writeResponse(w, r, response)
		return
	}

	scheme := "https"
	_ = scheme
	if r.TLS == nil {
		scheme = "http"
	}

	const dateFormat = "2006-01-02"
	const zuluTimeFormat = "2006-01-02T150405.999999999Z"
	const timeFormat = "2006-01-02T150405.999999999-0700"
	var fromEdited, beforeEdited, fromCreated, beforeCreated time.Time
	response.From = r.Form.Get("from")
	response.Before = r.Form.Get("before")
	if r.Form.Has("fromEdited") {
		s := r.Form.Get("fromEdited")
		if len(s) == len(dateFormat) {
			fromEdited, err = time.ParseInLocation(dateFormat, s, time.UTC)
			if err == nil {
				response.FromEdited = fromEdited.Format(dateFormat)
			}
		} else if strings.HasSuffix(s, "Z") {
			fromEdited, err = time.ParseInLocation(zuluTimeFormat, s, time.UTC)
			if err == nil {
				response.FromEdited = fromEdited.Format(zuluTimeFormat)
			}
		} else {
			fromEdited, err = time.ParseInLocation(timeFormat, s, time.UTC)
			if err == nil {
				response.FromEdited = fromEdited.Format(timeFormat)
			}
		}
	}
	if r.Form.Has("beforeEdited") {
		s := r.Form.Get("beforeEdited")
		if len(s) == len(dateFormat) {
			beforeEdited, err = time.ParseInLocation(dateFormat, s, time.UTC)
			if err == nil {
				response.BeforeEdited = beforeEdited.Format(dateFormat)
			}
		} else if strings.HasSuffix(s, "Z") {
			beforeEdited, err = time.ParseInLocation(zuluTimeFormat, s, time.UTC)
			if err == nil {
				response.BeforeEdited = beforeEdited.Format(zuluTimeFormat)
			}
		} else {
			beforeEdited, err = time.ParseInLocation(timeFormat, s, time.UTC)
			if err == nil {
				response.BeforeEdited = beforeEdited.Format(timeFormat)
			}
		}
	}
	if r.Form.Has("fromCreated") {
		s := r.Form.Get("fromCreated")
		if len(s) == len(dateFormat) {
			fromCreated, err = time.ParseInLocation(dateFormat, s, time.UTC)
			if err == nil {
				response.FromCreated = fromCreated.Format(dateFormat)
			}
		} else if strings.HasSuffix(s, "Z") {
			fromCreated, err = time.ParseInLocation(zuluTimeFormat, s, time.UTC)
			if err == nil {
				response.FromCreated = fromCreated.Format(zuluTimeFormat)
			}
		} else {
			fromCreated, err = time.ParseInLocation(timeFormat, s, time.UTC)
			if err == nil {
				response.FromCreated = fromCreated.Format(timeFormat)
			}
		}
	}
	if r.Form.Has("beforeCreated") {
		s := r.Form.Get("beforeCreated")
		if len(s) == len(dateFormat) {
			beforeCreated, err = time.ParseInLocation(dateFormat, s, time.UTC)
			if err == nil {
				response.BeforeCreated = beforeCreated.Format(dateFormat)
			}
		} else if strings.HasSuffix(s, "Z") {
			beforeCreated, err = time.ParseInLocation(zuluTimeFormat, s, time.UTC)
			if err == nil {
				response.BeforeCreated = beforeCreated.Format(zuluTimeFormat)
			}
		} else {
			beforeCreated, err = time.ParseInLocation(timeFormat, s, time.UTC)
			if err == nil {
				response.BeforeCreated = beforeCreated.Format(timeFormat)
			}
		}
	}
	response.Limit, _ = strconv.Atoi(r.Form.Get("limit"))
	if response.Limit <= 0 {
		response.Limit = 200
	}

	group, groupctx := errgroup.WithContext(r.Context())
	group.Go(func() error {
		pinnedFiles, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM pinned_file" +
				" JOIN files ON files.file_id = pinned_file.file_id" +
				" WHERE pinned_file.parent_id = (SELECT file_id FROM files WHERE file_path = {filePath})" +
				" ORDER BY files.file_path",
			Values: []any{
				sq.StringParam("filePath", path.Join(sitePrefix, filePath)),
			},
		}, func(row *sq.Row) File {
			filePath := row.String("files.file_path")
			return File{
				FileID:       row.UUID("files.file_id"),
				Parent:       strings.Trim(strings.TrimPrefix(path.Dir(filePath), sitePrefix), "/"),
				Name:         path.Base(filePath),
				Size:         row.Int64("files.size"),
				ModTime:      row.Time("files.mod_time"),
				CreationTime: row.Time("files.creation_time"),
				IsDir:        row.Bool("files.is_dir"),
			}
		})
		if err != nil {
			return err
		}
		response.PinnedFiles = pinnedFiles
		return nil
	})
	switch response.Sort {
	case "name":
		if response.From != "" && response.Before != "" {
		} else if response.From != "" {
		} else if response.Before != "" {
		}
	case "edited":
		if response.FromEdited != "" && response.BeforeEdited != "" {
		} else if response.FromEdited != "" {
		} else if response.BeforeEdited != "" {
		}
	case "created":
		if response.FromCreated != "" && response.BeforeCreated != "" {
		} else if response.FromCreated != "" {
		} else if response.BeforeCreated != "" {
		}
	}
	err = group.Wait()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	writeResponse(w, r, response)
}
