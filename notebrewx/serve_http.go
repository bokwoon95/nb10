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
	urlPath := strings.Trim(r.URL.Path, "/")
	if urlPath == "signup" {
		securityHeaders(w, nbrew.CMSDomainHTTPS)
		nbrew.signup(w, r.WithContext(loggerCtx))
		return
	}
	head, tail, _ := strings.Cut(urlPath, "/")
	if head == "users" {
		switch tail {
		case "login":
		case "profile":
		case "billing":
			securityHeaders(w, nbrew.CMSDomainHTTPS)
			return
		}
	}
	nbrew.Notebrew.ServeHTTP(w, r)
}

func securityHeaders(w http.ResponseWriter, cmsDomainHTTPS bool) {
	w.Header().Add("X-Frame-Options", "DENY")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Add("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
	w.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Add("Cross-Origin-Embedder-Policy", "credentialless")
	w.Header().Add("Cross-Origin-Resource-Policy", "cross-origin")
	if cmsDomainHTTPS {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
}
