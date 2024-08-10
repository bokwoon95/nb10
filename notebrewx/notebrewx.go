package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/bokwoon95/nb10"
)

var (
	//go:embed embed
	embedFS embed.FS

	runtimeFS fs.FS = embedFS
)

type Notebrewx struct {
	*nb10.Notebrew

	StripeConfig struct {
		PublishableKey string
		SecretKey      string
	}

	Mailer *Mailer
}

func NewNotebrewx(configDir string, nbrew *nb10.Notebrew) (*Notebrewx, error) {
	nbrewx := &Notebrewx{
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
		nbrewx.StripeConfig.PublishableKey = stripeConfig.PublishableKey
		nbrewx.StripeConfig.SecretKey = stripeConfig.SecretKey
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
		mailerConfig := MailerConfig{
			Username: smtpConfig.Username,
			Password: smtpConfig.Password,
			Host:     smtpConfig.Host,
			Port:     smtpConfig.Port,
			MailFrom: smtpConfig.MailFrom,
			Logger:   nbrew.Logger,
		}
		if smtpConfig.LimitInterval == "" {
			mailerConfig.LimitInterval = 12 * time.Second // 300 events per hour (3600 seconds) => 12 seconds between events
		} else {
			limitInterval, err := time.ParseDuration(smtpConfig.LimitInterval)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
			}
			mailerConfig.LimitInterval = limitInterval
		}
		if smtpConfig.LimitBurst <= 0 {
			mailerConfig.LimitBurst = 150
		} else {
			mailerConfig.LimitBurst = smtpConfig.LimitBurst
		}
		mailer, err := NewMailer(mailerConfig)
		if err != nil {
			return nil, err
		}
		nbrewx.Mailer = mailer
	}
	return nbrewx, nil
}
