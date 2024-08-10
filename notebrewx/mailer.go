package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/smtp"
	"strings"
	"time"

	"github.com/bokwoon95/nb10/stacktrace"
	"golang.org/x/time/rate"
)

var (
	headerNameReplacer  = strings.NewReplacer(":", "", "\r\n", "")
	headerValueReplacer = strings.NewReplacer("\r\n", "")
)

type MailerConfig struct {
	Username      string
	Password      string
	Host          string
	Port          string
	MailFrom      string
	LimitInterval time.Duration
	LimitBurst    int
	Logger        *slog.Logger
}

type Mailer struct {
	Username      string
	Password      string
	Host          string
	Port          string
	MailFrom      string
	Limiter       *rate.Limiter
	C             chan Mail
	Logger        *slog.Logger
	baseCtx       context.Context
	baseCtxCancel func()
	stopped          chan struct{}
}

type Mail struct {
	MailFrom string
	RcptTo   string
	Headers  []string // make sure to populate: Reply-To, Subject, Content-Type
	Body     io.Reader
}

func NewMailer(config MailerConfig) (*Mailer, error) {
	baseCtx, baseCtxCancel := context.WithCancel(context.Background())
	mailer := &Mailer{
		Username:      config.Username,
		Password:      config.Password,
		Host:          config.Host,
		Port:          config.Port,
		MailFrom:      config.MailFrom,
		Limiter:       rate.NewLimiter(rate.Every(config.LimitInterval), config.LimitBurst),
		C:             make(chan Mail, config.LimitBurst),
		Logger:        config.Logger,
		baseCtx:       baseCtx,
		baseCtxCancel: baseCtxCancel,
		stopped:          make(chan struct{}),
	}
	go mailer.start()
	return mailer, nil
}

func (mailer *Mailer) NewClient() (*smtp.Client, error) {
	if mailer.Port == "465" {
		conn, err := tls.Dial("tcp", mailer.Host+":"+mailer.Port, &tls.Config{
			ServerName: mailer.Host,
		})
		if err != nil {
			return nil, stacktrace.New(err)
		}
		client, err := smtp.NewClient(conn, mailer.Host)
		if err != nil {
			return nil, stacktrace.New(err)
		}
		return client, nil
	}
	client, err := smtp.Dial(mailer.Host + ":" + mailer.Port)
	if err != nil {
		return nil, stacktrace.New(err)
	}
	if mailer.Port == "587" {
		err := client.StartTLS(&tls.Config{
			ServerName: mailer.Host,
		})
		if err != nil {
			return nil, stacktrace.New(err)
		}
	}
	err = client.Auth(smtp.PlainAuth("", mailer.Username, mailer.Password, mailer.Host))
	if err != nil {
		return nil, stacktrace.New(err)
	}
	return client, nil
}

func (mailer *Mailer) start() {
	defer close(mailer.stopped)
	timer := time.NewTimer(-1)
	defer timer.Stop()
	var buf bytes.Buffer
	for {
		select {
		case <-mailer.baseCtx.Done():
			return
		case mail := <-mailer.C:
			client, err := mailer.NewClient()
			if err != nil {
				mailer.Logger.Error(err.Error())
				break
			}
			quit := false
			for !quit {
				if mail.MailFrom != "" {
					err := client.Mail(mail.MailFrom)
					if err != nil {
						mailer.Logger.Error(err.Error())
						break
					}
				} else {
					err := client.Mail(mailer.MailFrom)
					if err != nil {
						mailer.Logger.Error(err.Error())
						break
					}
				}
				err := client.Rcpt(mail.RcptTo)
				if err != nil {
					mailer.Logger.Error(err.Error())
					break
				}
				buf.Reset()
				buf.WriteString("MIME-version: 1.0\r\n")
				buf.WriteString("From: " + headerValueReplacer.Replace(mail.MailFrom) + "\r\n")
				buf.WriteString("To: " + headerValueReplacer.Replace(mail.RcptTo) + "\r\n")
				for i := 0; i+1 < len(mail.Headers); i += 2 {
					name, value := mail.Headers[i], mail.Headers[i+1]
					buf.WriteString(headerNameReplacer.Replace(name) + ": " + headerValueReplacer.Replace(value) + "\r\n")
				}
				buf.WriteString("\r\n")
				writer, err := client.Data()
				if err != nil {
					mailer.Logger.Error(err.Error())
					break
				}
				_, err = io.Copy(writer, &buf)
				if err != nil {
					writer.Close()
					mailer.Logger.Error(err.Error())
					break
				}
				_, err = io.Copy(writer, mail.Body)
				if err != nil {
					writer.Close()
					mailer.Logger.Error(err.Error())
					break
				}
				err = writer.Close()
				if err != nil {
					mailer.Logger.Error(err.Error())
					break
				}
				timer.Reset(100 * time.Second)
				select {
				case <-mailer.baseCtx.Done():
					return
				case <-timer.C:
					quit = true
				case mail = <-mailer.C:
					timer.Stop()
					err = client.Reset()
					if err != nil {
						mailer.Logger.Error(err.Error())
						quit = true
					}
				}
			}
			err = client.Quit()
			if err != nil {
				mailer.Logger.Error(err.Error())
				break
			}
		}
	}
}

func (mailer *Mailer) Close() error {
	mailer.baseCtxCancel()
	<-mailer.stopped
	return nil
}
