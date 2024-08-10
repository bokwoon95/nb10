package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/mail"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrewx) signup(w http.ResponseWriter, r *http.Request) {
	type Request struct {
		CaptchaResponse string
		Email           string
	}
	type Response struct {
		CaptchaWidgetScriptSrc template.URL `json:"captchaWidgetScriptSrc"`
		CaptchaWidgetClass     string       `json:"captchaWidgetClass"`
		CaptchaSiteKey         string       `json:"captchaSiteKey"`
		Email                  string       `json:"email"`
		Error                  string       `json:"error"`
		FormErrors             url.Values   `json:"formErrors"`
	}

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if r.Method == "HEAD" {
					w.WriteHeader(http.StatusOK)
					return
				}
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
				}
				return
			}
			funcMap := map[string]any{
				"join":       path.Join,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"contains":   strings.Contains,
				"stylesCSS":  func() template.CSS { return template.CSS(nb10.StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(nb10.BaselineJS) },
				"referer":    func() string { return r.Referer() },
			}
			tmpl, err := template.New("signup.html").Funcs(funcMap).ParseFS(runtimeFS, "embed/signup.html")
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}
		var response Response
		_, err := nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		response.CaptchaWidgetScriptSrc = nbrew.CaptchaConfig.WidgetScriptSrc
		response.CaptchaWidgetClass = nbrew.CaptchaConfig.WidgetClass
		response.CaptchaSiteKey = nbrew.CaptchaConfig.SiteKey
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		writeResponse(w, r, response)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				encoder := json.NewEncoder(w)
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
				}
				return
			}
			if response.Error != "" {
				err := nbrew.SetFlashSession(w, r, &response)
				if err != nil {
					nbrew.GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/signup/", http.StatusFound)
				return
			}
			err := nbrew.SetFlashSession(w, r, map[string]any{
				"email": response.Email,
			})
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/signup/success/", http.StatusFound)
		}

		var request Request
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				nbrew.BadRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(2 << 20 /* 2MB */)
				if err != nil {
					nbrew.BadRequest(w, r, err)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					nbrew.BadRequest(w, r, err)
					return
				}
			}
			request.Email = r.Form.Get("email")
			request.CaptchaResponse = r.Form.Get(nbrew.CaptchaConfig.ResponseTokenName)
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Email:      request.Email,
			FormErrors: url.Values{},
		}
		if request.CaptchaResponse == "" {
			response.Error = "RetryWithCaptcha"
			writeResponse(w, r, response)
			return
		}
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		values := url.Values{
			"secret":   []string{nbrew.CaptchaConfig.SecretKey},
			"response": []string{request.CaptchaResponse},
			"sitekey":  []string{nbrew.CaptchaConfig.SiteKey},
		}
		ip := nb10.RealClientIP(r, nbrew.ProxyConfig.RealIPHeaders, nbrew.ProxyConfig.ProxyIPs)
		if ip != (netip.Addr{}) {
			values.Set("remoteip", ip.String())
		}
		resp, err := client.Post(nbrew.CaptchaConfig.VerificationURL, "application/x-www-form-urlencoded", strings.NewReader(values.Encode()))
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer resp.Body.Close()
		result := make(map[string]any)
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		value := result["success"]
		if value == nil {
			b, err := json.Marshal(result)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
			} else {
				nbrew.GetLogger(r.Context()).Error(string(b))
			}
		}
		success, _ := value.(bool)
		if !success {
			response.Error = "CaptchaChallengeFailed"
			writeResponse(w, r, response)
			return
		}
		if response.Email == "" {
			response.FormErrors.Add("email", "required")
		} else {
			_, err := mail.ParseAddress(response.Email)
			if err != nil {
				response.FormErrors.Add("email", "invalid email address")
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT 1 FROM users WHERE email = {email}",
			Values: []any{
				sq.StringParam("email", response.Email),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if exists {
			response.Error = "UserAlreadyExists"
			writeResponse(w, r, response)
			return
		}
		// TODO: check if an invite link already exists for the given email.
		if !nbrew.Mailer.Limiter.Allow() {
			response.Error = "MailerRateLimited"
			writeResponse(w, r, response)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err = nbrew.Mailer.Limiter.Wait(ctx)
		if err != nil {
			response.Error = "MailerRateLimited"
			writeResponse(w, r, response)
			return
		}
		var inviteTokenBytes [8 + 16]byte
		binary.BigEndian.PutUint64(inviteTokenBytes[:8], uint64(time.Now().Unix()))
		_, err = rand.Read(inviteTokenBytes[8:])
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		checksum := blake2b.Sum256(inviteTokenBytes[8:])
		var inviteTokenHash [8 + blake2b.Size256]byte
		copy(inviteTokenHash[:8], inviteTokenBytes[:8])
		copy(inviteTokenHash[8:], checksum[:])
		_, err = sq.Exec(context.Background(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO invite (invite_token_hash, email, site_limit, storage_limit)" +
				" VALUES ({inviteTokenHash}, {email}, {siteLimit}, {storageLimit})",
			Values: []any{
				sq.BytesParam("inviteTokenHash", inviteTokenHash[:]),
				sq.Param("email", response.Email),
				sq.Param("siteLimit", 3),
				sq.Param("storageLimit", 10_000_000),
			},
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		scheme := "https://"
		if !nbrew.CMSDomainHTTPS {
			scheme = "http://"
		}
		mail := Mail{
			RcptTo: response.Email,
			Headers: []string{
				"Reply-To", "bokwoon.c@gmail.com",
				"Subject", "Welcome to notebrew!",
				"Content-Type", "text/html; charset=utf-8",
			},
			Body: strings.NewReader(fmt.Sprintf(
				"<p>Your notebrew invite link: <a href='%[1]s'>%[1]s</a></p>",
				scheme+nbrew.CMSDomain+"/users/invite/?token="+strings.TrimLeft(hex.EncodeToString(inviteTokenBytes[:]), "0"),
			)),
		}
		if nbrew.ReplyTo != "" {
			mail.Headers = append(mail.Headers, "Reply-To", nbrew.ReplyTo)
		}
		nbrew.Mailer.C <- mail
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}

func (nbrew *Notebrewx) signupSuccess(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		Email string `json:"email"`
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		nbrew.MethodNotAllowed(w, r)
		return
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if r.Form.Has("api") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			if r.Method == "HEAD" {
				w.WriteHeader(http.StatusOK)
				return
			}
			encoder := json.NewEncoder(w)
			encoder.SetIndent("", "  ")
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(&response)
			if err != nil {
				nbrew.GetLogger(r.Context()).Error(err.Error())
			}
			return
		}
		funcMap := map[string]any{
			"join":       path.Join,
			"hasPrefix":  strings.HasPrefix,
			"trimPrefix": strings.TrimPrefix,
			"contains":   strings.Contains,
			"stylesCSS":  func() template.CSS { return template.CSS(nb10.StylesCSS) },
			"baselineJS": func() template.JS { return template.JS(nb10.BaselineJS) },
			"referer":    func() string { return r.Referer() },
		}
		tmpl, err := template.New("signup_success.html").Funcs(funcMap).ParseFS(runtimeFS, "embed/signup_success.html")
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.ExecuteTemplate(w, r, tmpl, &response)
	}
	var response Response
	_, err := nbrew.GetFlashSession(w, r, &response)
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
	}
	writeResponse(w, r, response)
}
