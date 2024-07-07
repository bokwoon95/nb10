package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/bokwoon95/nb10"
)

var (
	//go:embed embed
	embedFS embed.FS

	runtimeFS fs.FS = embedFS
)

type Notebrew2 struct {
	*nb10.Notebrew

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

func NewNotebrew2(configDir string, nbrew *nb10.Notebrew) (*Notebrew2, error) {
	nbrew2 := &Notebrew2{
		Notebrew: nbrew,
	}
	// Stripe.
	b, err := os.ReadFile(filepath.Join(configDir, "stripe.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "stripe.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var stripeConfig StripeConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&stripeConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "stripe.json"), err)
		}
		nbrew2.StripeConfig.PublishableKey = stripeConfig.PublishableKey
		nbrew2.StripeConfig.SecretKey = stripeConfig.SecretKey
	}
	// SMTP.
	b, err = os.ReadFile(filepath.Join(configDir, "smtp.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var smtpConfig SMTPConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&smtpConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
		}
		nbrew2.SMTPConfig.Username = smtpConfig.Username
		nbrew2.SMTPConfig.Password = smtpConfig.Password
		nbrew2.SMTPConfig.Host = smtpConfig.Host
		nbrew2.SMTPConfig.Port = smtpConfig.Port
	}
	return nbrew2, nil
}

func (nbrew2 *Notebrew2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != nbrew2.Notebrew.CMSDomain {
		nbrew2.Notebrew.ServeHTTP(w, r)
		return
	}
	urlPath := strings.Trim(r.URL.Path, "/")
	if urlPath == "users/signup" {
	} else if strings.HasPrefix(urlPath, "users/signup/") {
	}
	nbrew2.Notebrew.ServeHTTP(w, r)
}
