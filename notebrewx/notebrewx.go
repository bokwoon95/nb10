package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/smtp"
	"os"
	"path/filepath"

	"github.com/bokwoon95/nb10"
	"golang.org/x/time/rate"
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

	SMTPConfig struct {
		Username string
		Password string
		Host     string
		Port     string
		MailFrom string
	}

	SMTPLimiter *rate.Limiter

	SMTPClient *smtp.Client
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
		nbrewx.SMTPConfig.Username = smtpConfig.Username
		nbrewx.SMTPConfig.Password = smtpConfig.Password
		nbrewx.SMTPConfig.Host = smtpConfig.Host
		nbrewx.SMTPConfig.Port = smtpConfig.Port
		nbrewx.SMTPConfig.MailFrom = smtpConfig.MailFrom
	}
	return nbrewx, nil
}

type contextKey struct{}

var loggerKey = &contextKey{}

func getLogger(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

func (nbrew *Notebrewx) Send() {
}
