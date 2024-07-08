package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)

func (nbrew *Notebrewx) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != nbrew.CMSDomain {
		nbrew.Notebrew.ServeHTTP(w, r)
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
	urlPath := strings.Trim(r.URL.Path, "/")
	if urlPath == "users/signup" {
	} else if strings.HasPrefix(urlPath, "users/signup/") {
	}
	nbrew.Notebrew.ServeHTTP(w, r)
}
