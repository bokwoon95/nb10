package nb10

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/nb10/sq"
)

func (nbrew *Notebrew) importt(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		TgzFileName            string `json:"tgzFileName"`
		Root                   string `json:"root"`
		OverwriteExistingFiles bool   `json:"overwriteExistingFiles"`
	}
	type Response struct {
		ContentBaseURL         string `json:"contentBaseURL"`
		CDNDomain              string `json:"cdnDomain"`
		IsDatabaseFS           bool   `json:"isDatabaseFS"`
		SitePrefix             string `json:"sitePrefix"`
		UserID                 ID     `json:"userID"`
		Username               string `json:"username"`
		DisableReason          string `json:"disableReason"`
		TgzFileName            string `json:"tgzFileName"`
		Root                   string `json:"root"`
		OverwriteExistingFiles bool   `json:"overwriteExistingFiles"`
		Size                   int64  `json:"size"`
		Error                  string `json:"error"`
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
				"ext":                   path.Ext,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"humanReadableFileSize": HumanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
			}
			tmpl, err := template.New("import.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/import.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}
		var response Response
		_, err := nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		response.ContentBaseURL = nbrew.ContentBaseURL(sitePrefix)
		response.CDNDomain = nbrew.CDNDomain
		_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.SitePrefix = sitePrefix
		response.TgzFileName = r.Form.Get("tgzFileName")
		if !strings.HasSuffix(response.TgzFileName, ".tgz") {
			response.Error = "InvalidFileType"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "imports", response.TgzFileName))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "FileNotExist"
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if fileInfo.IsDir() {
			response.Error = "InvalidFileType"
			writeResponse(w, r, response)
			return
		}
		response.Size = fileInfo.Size()
		if nbrew.DB != nil {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM import_job WHERE site_id = (SELECT site_id FROM site WHERE site_name = {siteName})",
				Values: []any{
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			if exists {
				response.Error = "ImportLimitReached"
				writeResponse(w, r, response)
				return
			}
		}
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
			if response.Error != "" {
				err := nbrew.SetFlashSession(w, r, &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "import")+"/?tgzFileName="+url.QueryEscape(response.TgzFileName), http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"postRedirectGet": map[string]any{
					"from":        "import",
					"tgzFileName": response.TgzFileName,
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "imports")+"/", http.StatusFound)
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
			request.TgzFileName = r.Form.Get("tgzFileName")
			request.Root = r.Form.Get("root")
			request.OverwriteExistingFiles = r.Form.Has("overwriteExistingFiles")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			TgzFileName:            request.TgzFileName,
			Root:                   path.Clean(strings.Trim(request.Root, "/")),
			OverwriteExistingFiles: request.OverwriteExistingFiles,
		}
		fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "imports", response.TgzFileName))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "FileNotExist"
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if fileInfo.IsDir() {
			response.Error = "InvalidFileType"
			writeResponse(w, r, response)
			return
		}
		response.Size = fileInfo.Size()
		startTime := time.Now().UTC()
		if nbrew.DB == nil {
			err := nbrew.importTgz(r.Context(), ID{}, sitePrefix, response.TgzFileName, response.Root, response.OverwriteExistingFiles)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		} else {
			importJobID := NewID()
			_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO import_job (import_job_id, site_id, file_name, start_time, total_bytes)" +
					" VALUES ({importJobID}, (SELECT site_id FROM site WHERE site_name = {siteName}), {fileName}, {startTime}, {size})",
				Values: []any{
					sq.UUIDParam("importJobID", importJobID),
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
					sq.StringParam("tgzFileName", response.TgzFileName),
					sq.TimeParam("startTime", startTime),
					sq.Int64Param("size", response.Size),
				},
			})
			if err != nil {
				if nbrew.ErrorCode != nil {
					errorCode := nbrew.ErrorCode(err)
					if IsKeyViolation(nbrew.Dialect, errorCode) {
						response.Error = "ImportLimitReached"
						writeResponse(w, r, response)
						return
					}
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			nbrew.waitGroup.Add(1)
			logger := getLogger(r.Context())
			go func() {
				defer func() {
					if v := recover(); v != nil {
						fmt.Println("panic:\n" + string(debug.Stack()))
					}
				}()
				defer nbrew.waitGroup.Done()
				err := nbrew.importTgz(nbrew.ctx, importJobID, sitePrefix, response.TgzFileName, response.Root, response.OverwriteExistingFiles)
				if err != nil {
					logger.Error(err.Error(),
						slog.String("importJobID", importJobID.String()),
						slog.String("sitePrefix", sitePrefix),
						slog.String("tgzFileName", response.TgzFileName),
						slog.String("root", response.Root),
						slog.Bool("overwriteExistingFiles", response.OverwriteExistingFiles),
					)
				}
			}()
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}

type importProgressReader struct {
	ctx            context.Context
	reader         io.Reader
	preparedExec   *sq.PreparedExec
	processedBytes int64
}

func (r *importProgressReader) Read(p []byte) (n int, err error) {
	err = r.ctx.Err()
	if err != nil {
		return 0, err
	}
	n, err = r.reader.Read(p)
	if r.preparedExec == nil {
		return n, err
	}
	processedBytes := r.processedBytes + int64(n)
	if processedBytes%(1<<20) > r.processedBytes%(1<<20) {
		result, err := r.preparedExec.Exec(r.ctx, sq.Int64Param("processedBytes", processedBytes))
		if err != nil {
			return n, err
		}
		// We weren't able to update the database row, which means it has been
		// deleted (i.e. job canceled).
		if result.RowsAffected == 0 {
			return n, fmt.Errorf("import canceled")
		}
	}
	r.processedBytes = processedBytes
	return n, err
}

func (nbrew *Notebrew) importTgz(ctx context.Context, importJobID ID, sitePrefix string, tgzFileName string, root string, overwriteExistingFiles bool) error {
	defer func() {
		if nbrew.DB == nil {
			return
		}
		_, err := sq.Exec(context.Background(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM import_job WHERE import_job_id = {importJobID}",
			Values: []any{
				sq.UUIDParam("importJobID", importJobID),
			},
		})
		if err != nil {
			nbrew.Logger.Error(err.Error())
		}
	}()
	file, err := nbrew.FS.WithContext(nbrew.ctx).Open(path.Join(sitePrefix, "imports", tgzFileName))
	if err != nil {
		return err
	}
	defer file.Close()
	var src io.Reader
	if nbrew.DB == nil {
		src = file
	} else {
		var db sq.DB
		if nbrew.Dialect == "sqlite" {
			db = nbrew.DB
		} else {
			var conn *sql.Conn
			conn, err = nbrew.DB.Conn(ctx)
			if err != nil {
				return err
			}
			defer conn.Close()
			db = conn
		}
		preparedExec, err := sq.PrepareExec(ctx, db, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "UPDATE import_job SET processed_bytes = {processedBytes} WHERE import_job_id = {importJobID}",
			Values: []any{
				sq.Int64Param("processedBytes", 0),
				sq.UUIDParam("importJobID", importJobID),
			},
		})
		if err != nil {
			return err
		}
		defer preparedExec.Close()
		src = &importProgressReader{
			ctx:            ctx,
			reader:         file,
			preparedExec:   preparedExec,
			processedBytes: 0,
		}
	}
	gzipReader, _ := gzipReaderPool.Get().(*gzip.Reader)
	if gzipReader == nil {
		gzipReader, err = gzip.NewReader(src)
		if err != nil {
			return err
		}
	} else {
		err = gzipReader.Reset(src)
		if err != nil {
			return err
		}
	}
	defer func() {
		gzipReader.Reset(empty)
		gzipReaderPool.Put(gzipReader)
	}()
	tarReader := tar.NewReader(gzipReader)
	var rootPrefix string
	if root != "." {
		rootPrefix = root + "/"
	}
	fsys := nbrew.FS.WithContext(ctx)
	regenerateSite := false
	mkdir := func(filePath string, modTime, creationTime time.Time, isPinned bool) error {
		if !overwriteExistingFiles {
			_, err := fs.Stat(fsys, filePath)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			} else {
				return nil
			}
		}
		if databaseFS, ok := fsys.(*DatabaseFS); ok {
			fsys = databaseFS.WithModTime(modTime).WithCreationTime(creationTime)
		}
		err := fsys.Mkdir(filePath, 0755)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return nil
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			err := fsys.MkdirAll(filePath, 0755)
			if err != nil {
				return err
			}
		}
		head, _, _ := strings.Cut(filePath, "/")
		if head == "posts" {
			regenerateSite = true
		}
		if databaseFS, ok := fsys.(*DatabaseFS); ok {
			if isPinned {
				switch databaseFS.Dialect {
				case "sqlite", "postgres":
					_, err := sq.Exec(ctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "INSERT INTO pinned_file (parent_id, file_id)" +
							" SELECT parent_id, file_id" +
							" FROM files" +
							" WHERE file_path = {filePath} AND parent_id IS NOT NULL" +
							" ON CONFLICT DO NOTHING",
						Values: []any{
							sq.Param("filePath", filePath),
						},
					})
					if err != nil {
						return err
					}
				case "mysql":
					_, err := sq.Exec(ctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "INSERT INTO pinned_file (parent_id, file_id)" +
							" SELECT parent_id, file_id" +
							" FROM files" +
							" WHERE file_path = {filePath} AND parent_id IS NOT NULL" +
							" ON DUPLICATE KEY UPDATE parent_id = parent_id",
						Values: []any{
							sq.Param("filePath", filePath),
						},
					})
					if err != nil {
						return err
					}
				default:
					return fmt.Errorf("unsupported dialect %q", databaseFS.Dialect)
				}
			}
		}
		return nil
	}
	writeFile := func(filePath string, modTime, creationTime time.Time, caption string, isPinned bool, reader io.Reader) error {
		if !overwriteExistingFiles {
			_, err := fs.Stat(fsys, filePath)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			} else {
				return nil
			}
		}
		if databaseFS, ok := fsys.(*DatabaseFS); ok {
			fsys = databaseFS.WithModTime(modTime).WithCreationTime(creationTime).WithCaption(caption)
		}
		writer, err := fsys.OpenWriter(filePath, 0644)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			err := fsys.MkdirAll(path.Dir(filePath), 0755)
			if err != nil {
				return err
			}
			writer, err = fsys.OpenWriter(filePath, 0644)
			if err != nil {
				return err
			}
		}
		defer writer.Close()
		_, err = io.Copy(writer, reader)
		if err != nil {
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		head, _, _ := strings.Cut(filePath, "/")
		if head == "pages" || head == "posts" {
			regenerateSite = true
		}
		if databaseFS, ok := fsys.(*DatabaseFS); ok {
			if isPinned {
				switch databaseFS.Dialect {
				case "sqlite", "postgres":
					_, err := sq.Exec(ctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "INSERT INTO pinned_file (parent_id, file_id)" +
							" SELECT parent_id, file_id" +
							" FROM files" +
							" WHERE file_path = {filePath} AND parent_id IS NOT NULL" +
							" ON CONFLICT DO NOTHING",
						Values: []any{
							sq.Param("filePath", filePath),
						},
					})
					if err != nil {
						return err
					}
				case "mysql":
					_, err := sq.Exec(ctx, databaseFS.DB, sq.Query{
						Dialect: databaseFS.Dialect,
						Format: "INSERT INTO pinned_file (parent_id, file_id)" +
							" SELECT parent_id, file_id" +
							" FROM files" +
							" WHERE file_path = {filePath} AND parent_id IS NOT NULL" +
							" ON DUPLICATE KEY UPDATE parent_id = parent_id",
						Values: []any{
							sq.Param("filePath", filePath),
						},
					})
					if err != nil {
						return err
					}
				default:
					return fmt.Errorf("unsupported dialect %q", databaseFS.Dialect)
				}
			}
		}
		return nil
	}
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(header.Name, rootPrefix) {
			continue
		}
		head, tail, _ := strings.Cut(header.Name, "/")
		fileType, ok := AllowedFileTypes[path.Ext(header.Name)]
		if !ok {
			continue
		}
		modTime := header.ModTime
		if s, ok := header.PAXRecords["NOTEBREW.file.modTime"]; ok {
			t, err := time.Parse("2006-01-02T15:04:05Z", s)
			if err == nil {
				modTime = t
			}
		}
		creationTime := header.ModTime
		if s, ok := header.PAXRecords["NOTEBREW.file.creationTime"]; ok {
			t, err := time.Parse("2006-01-02T15:04:05Z", s)
			if err == nil {
				creationTime = t
			}
		}
		isPinned := false
		if s, ok := header.PAXRecords["NOTEBREW.file.isPinned"]; ok {
			b, err := strconv.ParseBool(s)
			if err == nil {
				isPinned = b
			}
		}
		caption := ""
		if fileType.Has(AttributeImg) {
			if s, ok := header.PAXRecords["NOTEBREW.file.caption"]; ok {
				caption = s
			}
		}
		switch head {
		case "notes":
			switch header.Typeflag {
			case tar.TypeDir:
				err := mkdir(path.Join(sitePrefix, header.Name), modTime, creationTime, isPinned)
				if err != nil {
					return err
				}
			case tar.TypeReg:
				if !fileType.Has(AttributeEditable) && !fileType.Has(AttributeImg) && !fileType.Has(AttributeFont) {
					continue
				}
				err := writeFile(path.Join(sitePrefix, header.Name), modTime, creationTime, caption, isPinned, io.LimitReader(tarReader, fileType.Limit))
				if err != nil {
					return err
				}
			}
		case "pages":
			switch header.Typeflag {
			case tar.TypeDir:
				err := mkdir(path.Join(sitePrefix, header.Name), modTime, creationTime, isPinned)
				if err != nil {
					return err
				}
			case tar.TypeReg:
				if fileType.Ext != ".html" {
					continue
				}
				if tail == "" && (tgzFileName == "posts.html" || tgzFileName == "themes.html") {
					continue
				}
				err := writeFile(path.Join(sitePrefix, header.Name), modTime, creationTime, caption, isPinned, io.LimitReader(tarReader, fileType.Limit))
				if err != nil {
					return err
				}
				regenerateSite = true
			}
		case "posts":
			switch header.Typeflag {
			case tar.TypeDir:
				category := tail
				if strings.Contains(category, "/") {
					continue
				}
				err := mkdir(path.Join(sitePrefix, header.Name), modTime, creationTime, isPinned)
				if err != nil {
					return err
				}
				regenerateSite = true
			case tar.TypeReg:
				category := path.Dir(tail)
				if strings.Contains(category, "/") {
					continue
				}
				baseName := path.Base(header.Name)
				if fileType.Ext != ".md" && baseName != "postlist.json" && baseName != "postlist.html" && baseName != "post.html" {
					continue
				}
				err := writeFile(path.Join(sitePrefix, header.Name), modTime, creationTime, caption, isPinned, io.LimitReader(tarReader, fileType.Limit))
				if err != nil {
					return err
				}
				regenerateSite = true
			}
		case "output":
			switch header.Typeflag {
			case tar.TypeDir:
				err := mkdir(path.Join(sitePrefix, header.Name), modTime, creationTime, isPinned)
				if err != nil {
					return err
				}
			case tar.TypeReg:
				if !fileType.Has(AttributeEditable) && !fileType.Has(AttributeImg) && !fileType.Has(AttributeFont) {
					continue
				}
				err := writeFile(path.Join(sitePrefix, header.Name), modTime, creationTime, caption, isPinned, io.LimitReader(tarReader, fileType.Limit))
				if err != nil {
					return err
				}
			}
		default:
			switch header.Typeflag {
			case tar.TypeReg:
				if header.Name != "site.json" {
					continue
				}
				err := writeFile(path.Join(sitePrefix, header.Name), modTime, creationTime, caption, isPinned, io.LimitReader(tarReader, fileType.Limit))
				if err != nil {
					return err
				}
			}
		}
	}
	if regenerateSite {
		_, err = nbrew.RegenerateSite(ctx, sitePrefix)
		if err != nil {
			return err
		}
	}
	return nil
}
