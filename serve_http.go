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
	"net/http"
	"path"
	"runtime/debug"
	"strings"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"github.com/caddyserver/certmagic"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := "https://"
	if nbrew.CMSDomain == "localhost" || strings.HasPrefix(nbrew.CMSDomain, "localhost:") {
		scheme = "http://"
	}

	defer func() {
		if v := recover(); v != nil {
			fmt.Println(r.Method + " " + scheme + r.Host + r.URL.RequestURI() + ":\n" + string(debug.Stack()))
		}
	}()

	// Redirect the www subdomain to the bare domain.
	if r.Host == "www."+nbrew.CMSDomain {
		http.Redirect(w, r, scheme+nbrew.CMSDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	// Clean the path and redirect if necessary.
	if r.Method == "GET" {
		cleanedPath := path.Clean(r.URL.Path)
		if cleanedPath != "/" && path.Ext(cleanedPath) == "" {
			cleanedPath += "/"
		}
		if cleanedPath != r.URL.Path {
			cleanedURL := *r.URL
			cleanedURL.Path = cleanedPath
			http.Redirect(w, r, cleanedURL.String(), http.StatusMovedPermanently)
			return
		}
	}
	urlPath := strings.Trim(r.URL.Path, "/")

	// Add request method and url to the logger.
	logger := nbrew.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(
		slog.String("method", r.Method),
		slog.String("url", scheme+r.Host+r.URL.RequestURI()),
	)
	r = r.WithContext(context.WithValue(r.Context(), loggerKey, logger))

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
	w.Header().Add("X-Frame-Options", "DENY")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Add("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
	w.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Add("Cross-Origin-Embedder-Policy", "require-corp")
	w.Header().Add("Cross-Origin-Resource-Policy", "same-origin")
	if nbrew.CMSDomain != "localhost" && !strings.HasPrefix(nbrew.CMSDomain, "localhost:") {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}

	if r.Method == "GET" {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		err := r.ParseForm()
		if err != nil {
			badRequest(w, r, err)
			return
		}
	}

	// Handle the /users/* route on the CMS domain.
	head, tail, _ := strings.Cut(urlPath, "/")
	if r.Host == nbrew.CMSDomain && head == "users" {
		switch tail {
		case "login":
			// nbrew.login(w, r, ip)
			return
		case "logout":
			// nbrew.logout(w, r, ip)
			return
		default:
			notFound(w, r)
			return
		}
	}

	// Handle the /files/* route on the CMS domain.
	if r.Host == nbrew.CMSDomain && head == "files" {
		urlPath := tail
		head, tail, _ := strings.Cut(urlPath, "/")
		if head == "static" {
			if r.Method != "GET" {
				methodNotAllowed(w, r)
				return
			}
			fileType, ok := fileTypes[path.Ext(urlPath)]
			if !ok {
				notFound(w, r)
				return
			}
			file, err := RuntimeFS.Open(urlPath)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			serveFile(w, r, file, fileInfo, fileType, "max-age: 2592000, stale-while-revalidate" /* 30 days */)
			return
		}

		// Figure out the sitePrefix of the site we are serving.
		var sitePrefix string
		tld := path.Ext(head)
		if strings.HasPrefix(head, "@") {
			sitePrefix, urlPath = head, tail
			head, tail, _ = strings.Cut(urlPath, "/")
		} else if tld != "" {
			// head is a sitePrefix only if its TLD is not a file extension.
			_, ok := fileTypes[tld]
			if !ok {
				sitePrefix, urlPath = head, tail
				head, tail, _ = strings.Cut(urlPath, "/")
			}
		}

		// If the users database is present, check if the user is authorized to
		// access the files for this site.
		var username string
		isAuthorizedForSite := true
		if nbrew.DB != nil {
			var authenticationTokenString string
			if r.Form.Has("api") {
				header := r.Header.Get("Authorization")
				if strings.HasPrefix(header, "Notebrew ") {
					authenticationTokenString = strings.TrimPrefix(header, "Notebrew ")
				}
			} else {
				cookie, _ := r.Cookie("authentication")
				if cookie != nil {
					authenticationTokenString = cookie.Value
				}
			}
			if authenticationTokenString == "" {
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				notAuthenticated(w, r)
				return
			}
			authenticationToken, err := hex.DecodeString(fmt.Sprintf("%048s", authenticationTokenString))
			if err != nil {
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				notAuthenticated(w, r)
				return
			}
			var authenticationTokenHash [8 + blake2b.Size256]byte
			checksum := blake2b.Sum256(authenticationToken[8:])
			copy(authenticationTokenHash[:8], authenticationToken[:8])
			copy(authenticationTokenHash[8:], checksum[:])
			result, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM authentication" +
					" JOIN users ON users.user_id = authentication.user_id" +
					" WHERE authentication.authentication_token_hash = {authenticationTokenHash}",
				Values: []any{
					sq.BytesParam("authenticationTokenHash", authenticationTokenHash[:]),
				},
			}, func(row *sq.Row) (result struct {
				Username            string
				IsAuthorizedForSite bool
			}) {
				result.Username = row.String("users.username")
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
					internalServerError(w, r, err)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Path:   "/",
					Name:   "authentication",
					Value:  "0",
					MaxAge: -1,
				})
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				notAuthenticated(w, r)
				return
			}
			username = result.Username
			isAuthorizedForSite = result.IsAuthorizedForSite
			logger := logger.With(slog.String("username", username))
			r = r.WithContext(context.WithValue(r.Context(), loggerKey, logger))
		}

		if sitePrefix == "" {
			switch urlPath {
			case "":
				nbrew.rootdirectory(w, r, username, "", time.Time{})
				return
			case "createsite":
				// nbrew.createsite(w, r, username)
				return
			case "deletesite":
				// nbrew.deletesite(w, r, username)
				return
			}
		}

		if !isAuthorizedForSite {
			notAuthorized(w, r)
			return
		}

		switch head {
		case "":
			nbrew.rootdirectory(w, r, username, sitePrefix, time.Time{})
			return
		case "posts":
			if path.Base(tail) == "postlist.json" {
				category := path.Dir(tail)
				nbrew.postlistJSON(w, r, username, sitePrefix, category)
				return
			}
			nbrew.file(w, r, username, sitePrefix, urlPath)
			return
		case "notes", "pages", "output":
			nbrew.file(w, r, username, sitePrefix, urlPath)
			return
		case "clipboard":
			// nbrew.clipboard(w, r, username, sitePrefix, tail)
			return
		}

		switch urlPath {
		case "site.json":
			nbrew.siteJSON(w, r, username, sitePrefix)
			return
		case "regenerate":
			// nbrew.regenerate(w, r, sitePrefix)
			return
		case "createfolder":
			// nbrew.createfolder(w, r, username, sitePrefix)
			return
		case "createfile":
			// nbrew.createfile(w, r, username, sitePrefix)
			return
		case "delete":
			// nbrew.delete(w, r, username, sitePrefix)
			return
		case "search":
			// nbrew.search(w, r, username, sitePrefix)
			return
		case "uploadfile":
			// nbrew.uploadfile(w, r, username, sitePrefix)
			return
		case "rename":
			// nbrew.rename(w, r, username, sitePrefix)
			return
		default:
			notFound(w, r)
			return
		}
	}

	// If we reach here, we are serving generated site content. Only GET
	// requests are allowed.
	if r.Method != "GET" {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Figure out the sitePrefix of the site we have to serve.
	var sitePrefix string
	var subdomain string
	if certmagic.MatchWildcard(r.Host, "*."+nbrew.ContentDomain) {
		subdomain = strings.TrimSuffix(r.Host, "."+nbrew.ContentDomain)
		if subdomain == "img" {
			// examples:
			// img.nbrew.io/foo/bar.jpg             => sitePrefix: <none>,      urlPath: foo/bar.jpg
			// img.nbrew.io/@username/foo/bar.jpg   => sitePrefix: @username,   urlPath: foo/bar.jpg
			// img.nbrew.io/example.com/foo/bar.jpg => sitePrefix: example.com, urlPath: foo/bar.jpg
			tld := path.Ext(head)
			if strings.HasPrefix(head, "@") {
				sitePrefix, urlPath = head, tail
			} else if tld != "" {
				// head is a sitePrefix only if its TLD is not a file
				// extension.
				_, ok := fileTypes[tld]
				if !ok {
					sitePrefix, urlPath = head, tail
				}
			}
		} else {
			sitePrefix = "@" + subdomain
		}
	} else if r.Host != nbrew.ContentDomain {
		sitePrefix = r.Host
	}

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
		fileType.IsGzippable = true
	} else {
		if path.Base(urlPath) == "index.html" {
			custom404(w, r, nbrew.FS, sitePrefix)
			return
		}
		filePath = path.Join(sitePrefix, "output", urlPath)
		fileType = fileTypes[ext]
		if fileType == (FileType{}) {
			custom404(w, r, nbrew.FS, sitePrefix)
			return
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
	switch fileType.Ext {
	case ".html":
		cacheControl = "no-cache, must-revalidate"
	case ".eot", ".otf", ".ttf", ".woff", ".woff2":
		cacheControl = "no-cache, stale-while-revalidate, max-age=2592000" /* 30 days */
	case ".jpeg", ".jpg", ".png", ".webp", ".gif":
		var isS3Storage bool
		if remoteFS, ok := nbrew.FS.(*RemoteFS); ok {
			_, isS3Storage = remoteFS.Storage.(*S3Storage)
		}
		if nbrew.ImgDomain != "" && isS3Storage {
			cacheControl = "max-age=31536000, immutable"
		} else {
			cacheControl = "no-cache, stale-while-revalidate, max-age=120" /* 2 minutes */
		}
	default:
		cacheControl = "no-cache, stale-while-revalidate, max-age=120" /* 2 minutes */
	}
	serveFile(w, r, file, fileInfo, fileType, cacheControl)
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
	if remoteFile, ok := file.(*RemoteFile); ok {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotFound)
		_, err := io.Copy(w, bytes.NewReader(remoteFile.buf.Bytes()))
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
	w.Header().Set("Cache-Control", "no-store")
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
