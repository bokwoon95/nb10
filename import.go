package nb10

import (
	"archive/tar"
	"compress/gzip"
	"context"
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
	"strings"
	"time"

	"github.com/bokwoon95/nb10/sq"
)

func (nbrew *Notebrew) importt(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		FileName               string `json:"fileName"`
		Root                   string `json:"root"`
		OverwriteExistingFiles bool   `json:"overwriteExistingFiles"`
	}
	type Response struct {
		ContentBaseURL         string `json:"contentBaseURL"`
		ImgDomain              string `json:"imgDomain"`
		IsDatabaseFS           bool   `json:"isDatabaseFS"`
		SitePrefix             string `json:"sitePrefix"`
		UserID                 ID     `json:"userID"`
		Username               string `json:"username"`
		FileName               string `json:"fileName"`
		Root                   string `json:"root"`
		OverwriteExistingFiles bool   `json:"overwriteExistingFiles"`
		Size                   int64  `json:"size"`
		Error                  string `json:"error"`
	}

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json")
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
			referer := nbrew.getReferer(r)
			funcMap := map[string]any{
				"join":                  path.Join,
				"base":                  path.Base,
				"ext":                   path.Ext,
				"hasPrefix":             strings.HasPrefix,
				"trimPrefix":            strings.TrimPrefix,
				"humanReadableFileSize": humanReadableFileSize,
				"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
				"referer":               func() string { return referer },
			}
			tmpl, err := template.New("import.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/import.html")
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
		response.FileName = r.Form.Get("fileName")
		if !strings.HasSuffix(response.FileName, ".tgz") {
			response.Error = "InvalidFileType"
			writeResponse(w, r, response)
			return
		}
		fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "imports", response.FileName))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "FileNotExist"
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
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
				nbrew.internalServerError(w, r, err)
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
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
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
			if response.Error != "" {
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/"+path.Join("files", sitePrefix, "import")+"/?fileName="+url.QueryEscape(response.FileName), http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":     "import",
					"fileName": response.FileName,
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
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
			request.FileName = r.Form.Get("fileName")
			request.Root = r.Form.Get("root")
			request.OverwriteExistingFiles = r.Form.Has("overwriteExistingFiles")
		default:
			nbrew.unsupportedContentType(w, r)
			return
		}

		response := Response{
			FileName:               request.FileName,
			Root:                   path.Clean(strings.Trim(request.Root, "/")),
			OverwriteExistingFiles: request.OverwriteExistingFiles,
		}
		fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(sitePrefix, "imports", response.FileName))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				response.Error = "FileNotExist"
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		if fileInfo.IsDir() {
			response.Error = "InvalidFileType"
			writeResponse(w, r, response)
			return
		}
		response.Size = fileInfo.Size()
		startTime := time.Now().UTC()
		importJobID := NewID()
		if nbrew.DB == nil {
			err := nbrew.doImport(r.Context(), importJobID, sitePrefix, response.FileName, response.Root, response.OverwriteExistingFiles)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		} else {
			_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO import_job (import_job_id, site_id, file_name, start_time, total_bytes)" +
					" VALUES ({importJobID}, (SELECT site_id FROM site WHERE site_name = {siteName}), {fileName}, {startTime}, {size})",
				Values: []any{
					sq.UUIDParam("importJobID", importJobID),
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
					sq.StringParam("fileName", response.FileName),
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
				nbrew.internalServerError(w, r, err)
				return
			}
			nbrew.waitGroup.Add(1)
			logger := getLogger(r.Context())
			go func() {
				defer nbrew.waitGroup.Done()
				err := nbrew.doImport(nbrew.ctx, importJobID, sitePrefix, response.FileName, response.Root, response.OverwriteExistingFiles)
				if err != nil {
					logger.Error(err.Error(),
						slog.String("importJobID", importJobID.String()),
						slog.String("sitePrefix", sitePrefix),
						slog.String("fileName", response.FileName),
						slog.String("root", response.Root),
						slog.Bool("overwriteExistingFiles", response.OverwriteExistingFiles),
					)
				}
			}()
		}
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}

type progressReader struct {
	ctx            context.Context
	reader         io.Reader
	preparedExec   *sq.PreparedExec
	processedBytes int64
}

func (r *progressReader) Read(p []byte) (n int, err error) {
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
		if result.RowsAffected == 0 {
			return n, fmt.Errorf("import canceled")
		}
	}
	r.processedBytes = processedBytes
	return n, nil
}

func (nbrew *Notebrew) doImport(ctx context.Context, importJobID ID, sitePrefix string, fileName string, root string, overwriteExistingFiles bool) error {
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
	file, err := nbrew.FS.WithContext(nbrew.ctx).Open(path.Join(sitePrefix, "imports", fileName))
	if err != nil {
		return err
	}
	defer file.Close()
	gzipReader, _ := gzipReaderPool.Get().(*gzip.Reader)
	if gzipReader == nil {
		gzipReader, err = gzip.NewReader(file)
		if err != nil {
			return err
		}
	} else {
		err = gzipReader.Reset(file)
		if err != nil {
			return err
		}
	}
	defer func() {
		gzipReader.Reset(empty)
		gzipReaderPool.Put(gzipReader)
	}()
	var prefix string
	if root != "." {
		prefix = root + "/"
	}
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(header.Name, prefix) {
			continue
		}
		head, _, _ := strings.Cut(header.Name, "/")
		ext := path.Ext(header.Name)
		switch head {
		case "notes":
			switch header.Typeflag {
			case tar.TypeDir:
				break
			case tar.TypeReg:
				switch ext {
				case ".html", ".css", ".js", ".md", ".txt", ".jpeg", ".jpg", ".png", ".gif":
					break
				default:
					continue
				}
			default:
				continue
			}
		case "pages":
			switch header.Typeflag {
			case tar.TypeDir:
				break
			case tar.TypeReg:
				switch ext {
				case ".html":
					break
				default:
					continue
				}
			default:
				continue
			}
		case "posts":
			switch header.Typeflag {
			case tar.TypeDir:
				break
			case tar.TypeReg:
				switch ext {
				case ".html", ".css", ".js", ".md", ".txt", ".jpeg", ".jpg", ".png", ".gif":
					break
				default:
					continue
				}
			default:
				continue
			}
		case "output":
		case "":
			switch header.Name {
			case "site.json":
				break
			default:
				continue
			}
		default:
			continue
		}
		_, err = fs.Stat(nbrew.FS.WithContext(ctx), path.Join(sitePrefix, header.Name))
		// TODO: make sure that the 1 MB limit is applied to text files and 10 MB limit is applied to image files.
	}
	return nil
}
