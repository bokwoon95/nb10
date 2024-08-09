package nb10

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"github.com/caddyserver/certmagic"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := "https://"
	if r.TLS == nil {
		scheme = "http://"
	}

	// Redirect the www subdomain to the bare domain.
	if r.Host == "www."+nbrew.CMSDomain {
		http.Redirect(w, r, scheme+nbrew.CMSDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	// Clean the path and redirect if necessary.
	var urlPath string
	if r.Method == "GET" || r.Method == "HEAD" {
		cleanedPath := path.Clean(r.URL.Path)
		if cleanedPath != "/" {
			_, ok := AllowedFileTypes[path.Ext(cleanedPath)]
			if !ok {
				cleanedPath += "/"
			}
		}
		if cleanedPath != r.URL.Path {
			cleanedURL := *r.URL
			cleanedURL.Path = cleanedPath
			http.Redirect(w, r, cleanedURL.String(), http.StatusMovedPermanently)
			return
		}
		urlPath = strings.Trim(cleanedPath, "/")
	} else {
		urlPath = strings.Trim(path.Clean(r.URL.Path), "/")
	}

	// TODO: we just call `urlPath := strings.Trim(path.Clean(r.URL.Path), "/")` here, leave the redirection logic to another handler.

	err := r.ParseForm()
	if err != nil {
		nbrew.BadRequest(w, r, err)
		return
	}

	// TODO: move this into a middleware that is called from main().
	// Add request method and url to the logger.
	logger := nbrew.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(
		slog.String("method", r.Method),
		slog.String("url", scheme+r.Host+r.URL.RequestURI()),
	)
	r = r.WithContext(context.WithValue(r.Context(), LoggerKey, logger))

	// TODO: move this into a middleware that is called from main().
	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
	w.Header().Add("X-Frame-Options", "DENY")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Add("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
	w.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Add("Cross-Origin-Embedder-Policy", "credentialless")
	w.Header().Add("Cross-Origin-Resource-Policy", "cross-origin")
	if nbrew.CMSDomainHTTPS {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}

	// Handle the /users/* route on the CMS domain.
	head, tail, _ := strings.Cut(urlPath, "/")
	if r.Host == nbrew.CMSDomain && head == "users" {
		if nbrew.DB == nil {
			nbrew.NotFound(w, r)
			return
		}
		var user User
		var sessionToken string
		header := r.Header.Get("Authorization")
		if header != "" {
			if strings.HasPrefix(header, "Bearer ") {
				sessionToken = strings.TrimPrefix(header, "Bearer ")
			}
		} else {
			cookie, _ := r.Cookie("session")
			if cookie != nil {
				sessionToken = cookie.Value
			}
		}
		if sessionToken != "" {
			sessionTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", sessionToken))
			if err == nil && len(sessionTokenBytes) == 24 {
				var sessionTokenHash [8 + blake2b.Size256]byte
				checksum := blake2b.Sum256(sessionTokenBytes[8:])
				copy(sessionTokenHash[:8], sessionTokenBytes[:8])
				copy(sessionTokenHash[8:], checksum[:])
				user, err = sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
					Dialect: nbrew.Dialect,
					Format: "SELECT {*}" +
						" FROM session" +
						" JOIN users ON users.user_id = session.user_id" +
						" WHERE session.session_token_hash = {sessionTokenHash}",
					Values: []any{
						sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
					},
				}, func(row *sq.Row) User {
					return User{
						UserID:                row.UUID("users.user_id"),
						Username:              row.String("users.username"),
						Email:                 row.String("users.email"),
						TimezoneOffsetSeconds: row.Int("users.timezone_offset_seconds"),
						DisableReason:         row.String("users.disable_reason"),
						SiteLimit:             row.Int64("coalesce(users.site_limit, -1)"),
						StorageLimit:          row.Int64("coalesce(users.storage_limit, -1)"),
					}
				})
				if err != nil {
					if !errors.Is(err, sql.ErrNoRows) {
						logger.Error(err.Error())
						nbrew.InternalServerError(w, r, err)
						return
					}
				}
			}
		}
		switch tail {
		case "invite":
			nbrew.invite(w, r, user)
			return
		case "login":
			nbrew.login(w, r, user)
			return
		case "logout":
			nbrew.logout(w, r, user)
			return
		case "resetpassword":
			nbrew.resetpassword(w, r, user)
			return
		}
		if user.UserID.IsZero() {
			nbrew.NotAuthenticated(w, r)
			return
		}
		switch tail {
		case "changepassword":
			nbrew.changepassword(w, r, user)
			return
		case "profile":
			nbrew.profile(w, r, user)
			return
		case "updateprofile":
			nbrew.updateprofile(w, r, user)
			return
		case "updateemail":
			nbrew.updateemail(w, r, user)
			return
		case "deletesession":
			nbrew.deletesession(w, r, user)
			return
		case "createsession":
			nbrew.createsession(w, r, user)
			return
		default:
			nbrew.NotFound(w, r)
			return
		}
	}

	// Handle the /files/* route on the CMS domain.
	if r.Host == nbrew.CMSDomain && head == "files" {
		urlPath := tail
		head, tail, _ := strings.Cut(urlPath, "/")
		if head == "static" {
			if r.Method != "GET" {
				nbrew.MethodNotAllowed(w, r)
				return
			}
			fileType, ok := AllowedFileTypes[path.Ext(urlPath)]
			if !ok {
				nbrew.NotFound(w, r)
				return
			}
			file, err := RuntimeFS.Open(urlPath)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					nbrew.NotFound(w, r)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			ServeFile(w, r, path.Base(urlPath), fileInfo.Size(), fileType, file, "max-age=31536000, immutable" /* 1 year */)
			return
		}

		// Figure out the sitePrefix of the site we are serving.
		var sitePrefix string
		if strings.HasPrefix(head, "@") {
			sitePrefix, urlPath = head, tail
			head, tail, _ = strings.Cut(urlPath, "/")
		} else {
			tld := path.Ext(head)
			if tld != "" {
				// head is a sitePrefix only if its TLD is not a file extension.
				_, ok := AllowedFileTypes[tld]
				if !ok {
					sitePrefix, urlPath = head, tail
					head, tail, _ = strings.Cut(urlPath, "/")
				}
			}
		}

		// If the users database is present, check if the user is authorized to
		// access the files for this site.
		user := User{
			SiteLimit:    -1,
			StorageLimit: -1,
		}
		isAuthorizedForSite := true
		if nbrew.DB != nil {
			var sessionToken string
			header := r.Header.Get("Authorization")
			if header != "" {
				if strings.HasPrefix(header, "Bearer ") {
					sessionToken = strings.TrimPrefix(header, "Bearer ")
				}
			} else {
				cookie, _ := r.Cookie("session")
				if cookie != nil {
					sessionToken = cookie.Value
				}
			}
			if sessionToken == "" {
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				nbrew.NotAuthenticated(w, r)
				return
			}
			sessionTokenBytes, err := hex.DecodeString(fmt.Sprintf("%048s", sessionToken))
			if err != nil {
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				nbrew.NotAuthenticated(w, r)
				return
			}
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionTokenBytes[8:])
			copy(sessionTokenHash[:8], sessionTokenBytes[:8])
			copy(sessionTokenHash[8:], checksum[:])
			result, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM session" +
					" JOIN users ON users.user_id = session.user_id" +
					" WHERE session.session_token_hash = {sessionTokenHash}",
				Values: []any{
					sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
				},
			}, func(row *sq.Row) (result struct {
				User
				IsAuthorizedForSite bool
			}) {
				result.UserID = row.UUID("users.user_id")
				result.Username = row.String("users.username")
				result.TimezoneOffsetSeconds = row.Int("users.timezone_offset_seconds")
				result.DisableReason = row.String("users.disable_reason")
				result.SiteLimit = row.Int64("coalesce(users.site_limit, -1)")
				result.StorageLimit = row.Int64("coalesce(users.storage_limit, -1)")
				result.IsAuthorizedForSite = row.Bool("EXISTS (SELECT 1"+
					" FROM site"+
					" JOIN site_user ON site_user.site_id = site.site_id"+
					" WHERE site.site_name = {siteName}"+
					" AND site_user.user_id = users.user_id"+
					")",
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
				)
				return result
			})
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					logger.Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				nbrew.NotAuthenticated(w, r)
				return
			}
			user = result.User
			isAuthorizedForSite = result.IsAuthorizedForSite
			logger := logger.With(slog.String("username", user.Username))
			r = r.WithContext(context.WithValue(r.Context(), LoggerKey, logger))
		}

		if sitePrefix == "" {
			switch urlPath {
			case "":
				nbrew.rootdirectory(w, r, user, "", time.Time{})
				return
			case "createsite":
				nbrew.createsite(w, r, user)
				return
			case "deletesite":
				nbrew.deletesite(w, r, user)
				return
			case "calculatestorage":
				nbrew.calculatestorage(w, r, user)
				return
			}
		}

		if !isAuthorizedForSite {
			nbrew.NotAuthorized(w, r)
			return
		}

		switch head {
		case "":
			nbrew.rootdirectory(w, r, user, sitePrefix, time.Time{})
			return
		case "notes", "pages", "posts", "output":
			if head == "posts" && path.Base(tail) == "postlist.json" {
				category := path.Dir(tail)
				if category == "." {
					category = ""
				}
				nbrew.postlistJSON(w, r, user, sitePrefix, category)
				return
			}
			fileType := AllowedFileTypes[path.Ext(urlPath)]
			if fileType.Has(AttributeImg) {
				fileInfo, err := fs.Stat(nbrew.FS.WithContext(r.Context()), path.Join(".", sitePrefix, urlPath))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						nbrew.NotFound(w, r)
						return
					}
					getLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				if fileInfo.IsDir() {
					nbrew.directory(w, r, user, sitePrefix, urlPath, fileInfo)
					return
				}
				nbrew.image(w, r, user, sitePrefix, urlPath, fileInfo)
				return
			}
			file, err := nbrew.FS.WithContext(r.Context()).Open(path.Join(".", sitePrefix, urlPath))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					nbrew.NotFound(w, r)
					return
				}
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			if fileInfo.IsDir() {
				nbrew.directory(w, r, user, sitePrefix, urlPath, fileInfo)
				return
			}
			nbrew.file(w, r, user, sitePrefix, urlPath, file, fileInfo)
			return
		case "clipboard":
			nbrew.clipboard(w, r, user, sitePrefix, tail)
			return
		case "imports":
			nbrew.imports(w, r, user, sitePrefix, tail)
			return
		case "exports":
			nbrew.exports(w, r, user, sitePrefix, tail)
			return
		}

		switch urlPath {
		case "site.json":
			nbrew.siteJSON(w, r, user, sitePrefix)
			return
		case "pin":
			nbrew.pin(w, r, user, sitePrefix)
			return
		case "unpin":
			nbrew.unpin(w, r, user, sitePrefix)
			return
		case "createfolder":
			nbrew.createfolder(w, r, user, sitePrefix)
			return
		case "createfile":
			nbrew.createfile(w, r, user, sitePrefix)
			return
		case "delete":
			nbrew.delet(w, r, user, sitePrefix)
			return
		case "search":
			nbrew.search(w, r, user, sitePrefix)
			return
		case "uploadfile":
			nbrew.uploadfile(w, r, user, sitePrefix)
			return
		case "rename":
			nbrew.rename(w, r, user, sitePrefix)
			return
		case "import":
			nbrew.importt(w, r, user, sitePrefix)
			return
		case "export":
			nbrew.export(w, r, user, sitePrefix)
			return
		case "cancelimport":
			nbrew.cancelimport(w, r, user, sitePrefix)
			return
		case "cancelexport":
			nbrew.cancelexport(w, r, user, sitePrefix)
			return
		case "applytheme":
			nbrew.applytheme(w, r, user, sitePrefix)
			return
		case "resettheme":
			nbrew.resettheme(w, r, user, sitePrefix)
			return
		default:
			nbrew.NotFound(w, r)
			return
		}
	}

	// If we reach here, we are serving generated site content. Only GET and
	// HEAD requests are allowed.
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Figure out the sitePrefix of the site we have to serve.
	var sitePrefix string
	var subdomain string
	if certmagic.MatchWildcard(r.Host, "*."+nbrew.ContentDomain) {
		subdomain = strings.TrimSuffix(r.Host, "."+nbrew.ContentDomain)
		if subdomain == "cdn" || subdomain == "storage" {
			databaseFS, ok := &DatabaseFS{}, false
			switch v := nbrew.FS.(type) {
			case interface{ As(any) bool }:
				ok = v.As(&databaseFS)
			}
			if !ok {
				http.Error(w, "404 Not Found", http.StatusNotFound)
				return
			}
			fileType, ok := AllowedFileTypes[path.Ext(urlPath)]
			if !ok || !fileType.Has(AttributeObject) || fileType.Ext == ".tgz" {
				http.Error(w, "404 Not Found", http.StatusNotFound)
			}
			reader, err := databaseFS.ObjectStorage.Get(r.Context(), urlPath)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrInvalid) {
					http.Error(w, "404 Not Found", http.StatusNotFound)
					return
				}
				logger.Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			defer reader.Close()
			if readSeeker, ok := reader.(io.ReadSeeker); ok {
				w.Header().Set("Content-Type", fileType.ContentType)
				w.Header().Set("Cache-Control", "max-age=31536000, immutable" /* 1 year */)
				http.ServeContent(w, r, "", time.Time{}, readSeeker)
				return
			}
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", "max-age=31536000, immutable" /* 1 year */)
			if r.Method == "HEAD" {
				w.WriteHeader(http.StatusOK)
				return
			}
			_, err = io.Copy(w, reader)
			if err != nil {
				logger.Error(err.Error())
			}
			return
		}
		sitePrefix = "@" + subdomain
	} else if r.Host != nbrew.ContentDomain {
		sitePrefix = r.Host
	}

	var ok bool
	var filePath string
	var fileType FileType
	ext := path.Ext(urlPath)
	if ext == "" {
		if subdomain == "www" {
			http.Redirect(w, r, scheme+nbrew.ContentDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}
		filePath = path.Join(sitePrefix, "output", urlPath, "index.html")
		fileType.Ext = ".html"
		fileType.ContentType = "text/html; charset=utf-8"
		fileType.Attribute |= AttributeGzippable
	} else {
		if path.Base(urlPath) == "index.html" {
			custom404(w, r, nbrew.FS, sitePrefix)
			return
		}
		fileType, ok = AllowedFileTypes[ext]
		if ok {
			filePath = path.Join(sitePrefix, "output", urlPath)
		} else {
			filePath = path.Join(sitePrefix, "output", urlPath, "index.html")
			fileType.Ext = ".html"
			fileType.ContentType = "text/html; charset=utf-8"
			fileType.Attribute |= AttributeGzippable
		}
	}
	file, err := nbrew.FS.Open(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			custom404(w, r, nbrew.FS, sitePrefix)
			return
		}
		logger.Error(err.Error())
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		logger.Error(err.Error())
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	if fileInfo.IsDir() {
		custom404(w, r, nbrew.FS, sitePrefix)
		return
	}
	var cacheControl string
	if fileType.Ext == ".html" {
		cacheControl = "no-cache"
	} else if fileType.Has(AttributeImg) || fileType.Has(AttributeFont) {
		cacheControl = "max-age=2592000, stale-while-revalidate=31536000" /* 1 month, 1 year */
	} else {
		cacheControl = "max-age=300, stale-while-revalidate=604800" /* 5 minutes, 1 week */
	}
	ServeFile(w, r, path.Base(filePath), fileInfo.Size(), fileType, file, cacheControl)
}

func custom404(w http.ResponseWriter, r *http.Request, fsys FS, sitePrefix string) {
	file, err := fsys.WithContext(r.Context()).Open(path.Join(sitePrefix, "output/404/index.html"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
		}
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	if databaseFile, ok := file.(*DatabaseFile); ok {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusNotFound)
		_, err := io.Copy(w, bytes.NewReader(databaseFile.buf.Bytes()))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(w)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusNotFound)
	_, err = io.Copy(gzipWriter, file)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	} else {
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
	}
}

func (nbrew *Notebrew) RedirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Use HTTPS", http.StatusBadRequest)
		return
	}
	// Redirect HTTP to HTTPS only if it isn't an API call.
	// https://jviide.iki.fi/http-redirects
	r.ParseForm()
	if r.Host != nbrew.CMSDomain || !r.Form.Has("api") {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		} else {
			host = net.JoinHostPort(host, "443")
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
		return
	}
	// If someone does make an api call via HTTP, revoke their
	// session token.
	var sessionTokenHashes [][]byte
	header := r.Header.Get("Authorization")
	if header != "" {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", strings.TrimPrefix(header, "Bearer ")))
		if err == nil && len(sessionToken) == 24 {
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionToken[8:])
			copy(sessionTokenHash[:8], sessionToken[:8])
			copy(sessionTokenHash[8:], checksum[:])
			sessionTokenHashes = append(sessionTokenHashes, sessionTokenHash[:])
		}
	}
	cookie, _ := r.Cookie("session")
	if cookie != nil && cookie.Value != "" {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
		if err == nil && len(sessionToken) == 24 {
			var sessionTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(sessionToken[8:])
			copy(sessionTokenHash[:8], sessionToken[:8])
			copy(sessionTokenHash[8:], checksum[:])
			sessionTokenHashes = append(sessionTokenHashes, sessionTokenHash[:])
		}
	}
	if len(sessionTokenHashes) > 0 {
		_, _ = sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM session WHERE session_token_hash IN ({sessionTokenHashes})",
			Values: []any{
				sq.Param("sessionTokenHashes", sessionTokenHashes),
			},
		})
	}
	http.Error(w, "Use HTTPS", http.StatusBadRequest)
}

func (nbrew *Notebrew) SecurityHeaders(w http.ResponseWriter, r *http.Request) {
	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
	w.Header().Add("X-Frame-Options", "DENY")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Add("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
	w.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Add("Cross-Origin-Embedder-Policy", "credentialless")
	w.Header().Add("Cross-Origin-Resource-Policy", "cross-origin")
	if nbrew.CMSDomainHTTPS {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
}
