package main

import (
	"context"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/bokwoon95/nb10"
)

func (nbrew *Notebrewx) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != nbrew.CMSDomain {
		nbrew.Notebrew.ServeHTTP(w, r)
		return
	}
	urlPath := strings.Trim(r.URL.Path, "/")
	if r.Method == "GET" || r.Method == "HEAD" {
		cleanedPath := path.Clean(r.URL.Path)
		if cleanedPath != "/" {
			_, ok := nb10.AllowedFileTypes[path.Ext(cleanedPath)]
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
	err := r.ParseForm()
	if err != nil {
		nbrew.BadRequest(w, r, err)
		return
	}
	scheme := "https://"
	if r.TLS == nil {
		scheme = "http://"
	}
	logger := nbrew.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(
		slog.String("method", r.Method),
		slog.String("url", scheme+r.Host+r.URL.RequestURI()),
	)
	loggerCtx := context.WithValue(r.Context(), loggerKey, logger)
	_ = loggerCtx
	if urlPath == "users/signup" {
	} else if strings.HasPrefix(urlPath, "users/signup/") {
	}
	nbrew.Notebrew.ServeHTTP(w, r)
}
