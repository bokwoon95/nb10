package main

import (
	"net/smtp"

	"golang.org/x/time/rate"
)

type Mailer struct {
	username string
	password string
	host     string
	port     string
	mailFrom string
	limiter  *rate.Limiter
	client   *smtp.Client
}
