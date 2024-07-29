package main

import (
	"encoding/json"
	"html/template"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/nb10"
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
					getLogger(r.Context()).Error(err.Error())
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
				getLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}
		var response Response
		_, err := nbrew.GetFlashSession(w, r, &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
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
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			if response.Error != "" {
				err := nbrew.SetFlashSession(w, r, &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, "/signup/", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/signupsuccess/", http.StatusFound)
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
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer resp.Body.Close()
		result := make(map[string]any)
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		value := result["success"]
		if value == nil {
			b, err := json.Marshal(result)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
			} else {
				getLogger(r.Context()).Error(string(b))
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
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		// TODO: captcha passed, now check if email already exists for user account.
		// TODO: if not exists, attempt to add the mail to the mail queue. If the mail queue rejects us, we set the response.Error to ServerBusyTryAgainLater
		// TODO: if we successfully manage to dump the mail into the queue, respond with a redirect to /signupsuccess/. No guarantee how fast the mail will reach the user, let's just hope it's fast enough.
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
