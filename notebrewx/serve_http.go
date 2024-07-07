package main

import (
	"net/http"
	"strings"
)

func (nbrew *Notebrewx) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != nbrew.CMSDomain {
		nbrew.Notebrew.ServeHTTP(w, r)
		return
	}
	urlPath := strings.Trim(r.URL.Path, "/")
	if urlPath == "users/signup" {
	} else if strings.HasPrefix(urlPath, "users/signup/") {
	}
	nbrew.Notebrew.ServeHTTP(w, r)
}
