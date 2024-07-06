package main

import (
	"net/http"
	"strings"

	"github.com/bokwoon95/nb10"
)

type SAAS struct {
	Notebrew *nb10.Notebrew

	StripeConfig struct {
		PublishableKey string
		SecretKey      string
	}

	SMTPConfig struct {
		Username string
		Password string
		Host     string
		Port     string
	}
}

func (saas *SAAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host == saas.Notebrew.CMSDomain {
		urlPath := strings.Trim(r.URL.Path, "/")
		if urlPath == "users/signup" {
		} else if strings.HasPrefix(urlPath, "users/signup/") {
		}
	}
	saas.Notebrew.ServeHTTP(w, r)
}
