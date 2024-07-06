package main

import (
	"net/http"
	"strings"

	"github.com/bokwoon95/nb10"
)

type Notebrew2 struct {
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

func NewNotebrew2(nbrew *nb10.Notebrew) (*Notebrew2, error) {
	nbrew2 := &Notebrew2{
		Notebrew: nbrew,
	}
	// TODO: read config from stripe.json and smtp.json.
	return nbrew2, nil
}

func (nbrew2 *Notebrew2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host == nbrew2.Notebrew.CMSDomain {
		urlPath := strings.Trim(r.URL.Path, "/")
		if urlPath == "users/signup" {
		} else if strings.HasPrefix(urlPath, "users/signup/") {
		}
	}
	nbrew2.Notebrew.ServeHTTP(w, r)
}
