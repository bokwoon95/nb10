package nb10

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) invite(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		Token           string `json:"token"`
		Username        string `json:"username"`
		Email           string `json:"email"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
		SiteName        string `json:"siteName"`
	}
	type Response struct {
		Token      string     `json:"token"`
		UserID     ID         `json:"userID"`
		Username   string     `json:"username"`
		Email      string     `json:"email"`
		SiteName   string     `json:"siteName"`
		Error      string     `json:"error"`
		FormErrors url.Values `json:"formErrors"`
	}

	switch r.Method {
	case "GET", "HEAD":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json")
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
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
			}
			tmpl, err := template.New("invite.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/invite.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.executeTemplate(w, r, tmpl, &response)
		}

		var response Response
		_, err := nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.UserID = user.UserID
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		if !user.UserID.IsZero() {
			response.Error = "AlreadyAuthenticated"
			writeResponse(w, r, response)
			return
		}
		s := r.Form.Get("token")
		if s == "" {
			response.Error = "MissingInviteToken"
			writeResponse(w, r, response)
			return
		}
		if len(s) > 48 {
			response.Error = "InvalidInviteToken"
			writeResponse(w, r, response)
			return
		}
		inviteToken, err := hex.DecodeString(fmt.Sprintf("%048s", s))
		if err != nil {
			response.Error = "InvalidInviteToken"
			writeResponse(w, r, response)
			return
		}
		checksum := blake2b.Sum256(inviteToken[8:])
		var inviteTokenHash [8 + blake2b.Size256]byte
		copy(inviteTokenHash[:8], inviteToken[:8])
		copy(inviteTokenHash[8:], checksum[:])
		exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT 1 FROM invite WHERE invite_token_hash = {inviteTokenHash}",
			Values: []any{
				sq.BytesParam("inviteTokenHash", inviteTokenHash[:]),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		if !exists {
			response.Error = "InvalidInviteToken"
			writeResponse(w, r, response)
			return
		}
		writeResponse(w, r, response)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json")
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
			if response.Error != "" {
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					nbrew.internalServerError(w, r, err)
					return
				}
				var query string
				if response.Token != "" {
					query = "?token=" + url.QueryEscape(response.Token)
				}
				http.Redirect(w, r, "/users/invite/"+query, http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from":     "invite",
					"username": response.Username,
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/users/login/", http.StatusFound)
		}

		var request Request
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				nbrew.badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
				if err != nil {
					nbrew.badRequest(w, r, err)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					nbrew.badRequest(w, r, err)
					return
				}
			}
			request.Token = r.Form.Get("token")
			request.Username = r.Form.Get("username")
			request.Email = r.Form.Get("email")
			request.Password = r.Form.Get("password")
			request.ConfirmPassword = r.Form.Get("confirmPassword")
			request.SiteName = r.Form.Get("siteName")
		default:
			nbrew.unsupportedContentType(w, r)
			return
		}

		response := Response{
			Token:      request.Token,
			Username:   request.Username,
			Email:      request.Email,
			SiteName:   request.SiteName,
			FormErrors: url.Values{},
		}
		// username
		if response.Username == "" {
			response.FormErrors.Add("username", "required")
		} else {
			for _, char := range response.Username {
				if char == ' ' {
					response.FormErrors.Add("username", "cannot include space")
					break
				}
				if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
					response.FormErrors.Add("username", fmt.Sprintf("cannot include character %q", string(char)))
					break
				}
			}
		}
		if !response.FormErrors.Has("username") {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM users WHERE username = {username}",
				Values: []any{
					sq.StringParam("username", response.Username),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			if exists {
				response.FormErrors.Add("username", "username already used by an existing user account")
			}
		}
		// email
		if response.Email == "" {
			response.FormErrors.Add("email", "required")
		} else {
			_, err := mail.ParseAddress(response.Email)
			if err != nil {
				response.FormErrors.Add("email", "invalid email address")
			}
		}
		if !response.FormErrors.Has("email") {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM users WHERE email = {email}",
				Values: []any{
					sq.StringParam("email", response.Email),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			if exists {
				response.FormErrors.Add("email", "email already used by an existing user account")
			}
		}
		// password
		if request.Password == "" {
			response.FormErrors.Add("password", "required")
		} else {
			if utf8.RuneCountInString(request.Password) < 8 {
				response.FormErrors.Add("password", "password must be at least 8 characters")
			}
			commonPasswords, err := getCommonPasswords()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			if _, ok := commonPasswords[request.Password]; ok {
				response.FormErrors.Add("password", "password is too common")
			}
		}
		// confirmPassword
		if !response.FormErrors.Has("password") {
			if request.ConfirmPassword == "" {
				response.FormErrors.Add("confirmPassword", "required")
			} else {
				if request.Password != request.ConfirmPassword {
					response.FormErrors.Add("confirmPassword", "password does not match")
				}
			}
		}
		if response.SiteName != "" {
			switch response.SiteName {
			case "www", "img", "video", "cdn", "storage":
				response.FormErrors.Add("siteName", "unavailable")
			default:
				for _, char := range response.SiteName {
					if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
						response.FormErrors.Add("siteName", fmt.Sprintf("cannot include character %q", string(char)))
						break
					}
				}
				if len(response.SiteName) > 30 {
					response.FormErrors.Add("siteName", "cannot exceed 30 characters")
				}
			}
		}
		if !response.FormErrors.Has("siteName") {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM site WHERE site_name = {siteName}",
				Values: []any{
					sq.StringParam("siteName", response.SiteName),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
			if exists {
				response.FormErrors.Add("siteName", "site name already in use")
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}

var getCommonPasswords = sync.OnceValues(func() (map[string]struct{}, error) {
	commonPasswords := make(map[string]struct{}, 10000)
	file, err := RuntimeFS.Open("embed/top-10000-passwords.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	done := false
	for {
		if done {
			break
		}
		line, err := reader.ReadBytes('\n')
		done = err == io.EOF
		if err != nil && !done {
			panic(err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		commonPasswords[string(line)] = struct{}{}
	}
	return commonPasswords, nil
})
