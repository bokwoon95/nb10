package main

import (
	"database/sql"
	"io"
	"net/smtp"

	"golang.org/x/time/rate"
)

type MailerConfig struct {
	Username string
	Password string
	Host     string
	Port     string
	MailFrom string
	DB       *sql.DB
	Dialect  string
}

type Mailer struct {
	username string
	password string
	host     string
	port     string
	mailFrom string
	limiter  *rate.Limiter
	client   *smtp.Client
}

func NewMailer() {
	// spins off a separate goroutine
}

func (mailer *Mailer) SendMail(rcptTo, subject string, body io.Reader) {
}
