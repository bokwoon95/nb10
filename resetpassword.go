package nb10

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) resetpassword(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		Token           string `json:"token"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	type Response struct {
		Token      string     `json:"token"`
		Error      string     `json:"error"`
		FormErrors url.Values `json:"formErrors"`
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
					GetLogger(r.Context()).Error(err.Error())
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
			tmpl, err := template.New("resetpassword.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/resetpassword.html")
			if err != nil {
				GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
			nbrew.ExecuteTemplate(w, r, tmpl, &response)
		}

		var response Response
		_, err := nbrew.GetSession(r, "flash", &response)
		if err != nil {
			GetLogger(r.Context()).Error(err.Error())
		}
		nbrew.ClearSession(w, r, "flash")
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		response.Token = r.Form.Get("token")
		if response.Token == "" {
			response.Error = "MissingResetToken"
			writeResponse(w, r, response)
			return
		}
		if len(response.Token) > 48 {
			response.Error = "InvalidResetToken"
			writeResponse(w, r, response)
			return
		}
		resetToken, err := hex.DecodeString(fmt.Sprintf("%048s", response.Token))
		if err != nil {
			response.Error = "InvalidResetToken"
			writeResponse(w, r, response)
			return
		}
		checksum := blake2b.Sum256(resetToken[8:])
		var resetTokenHash [8 + blake2b.Size256]byte
		copy(resetTokenHash[:8], resetToken[:8])
		copy(resetTokenHash[8:], checksum[:])
		exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT 1 FROM users WHERE reset_token_hash = {resetTokenHash}",
			Values: []any{
				sq.BytesParam("resetTokenHash", resetTokenHash[:]),
			},
		})
		if err != nil {
			GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if !exists {
			response.Error = "InvalidResetToken"
			writeResponse(w, r, response)
			return
		}
		writeResponse(w, r, response)
	case "POST":
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
					GetLogger(r.Context()).Error(err.Error())
				}
				return
			}
			if response.Error != "" {
				err := nbrew.SetSession(w, r, "flash", &response)
				if err != nil {
					GetLogger(r.Context()).Error(err.Error())
					nbrew.InternalServerError(w, r, err)
					return
				}
				var query string
				if response.Token != "" {
					query = "?token=" + url.QueryEscape(response.Token)
				}
				http.Redirect(w, r, "/users/resetpassword/"+query, http.StatusFound)
				return
			}
			err := nbrew.SetSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "resetpassword",
				},
			})
			if err != nil {
				GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
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
				nbrew.BadRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(1 << 20 /* 1 MB */)
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
			request.Token = r.Form.Get("token")
			request.Password = r.Form.Get("password")
			request.ConfirmPassword = r.Form.Get("confirmPassword")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			Token:      request.Token,
			FormErrors: url.Values{},
		}
		if response.Token == "" {
			response.Error = "MissingResetToken"
			writeResponse(w, r, response)
			return
		}
		if len(response.Token) > 48 {
			response.Error = "InvalidResetToken"
			writeResponse(w, r, response)
			return
		}
		resetToken, err := hex.DecodeString(fmt.Sprintf("%048s", response.Token))
		if err != nil {
			response.Error = "InvalidResetToken"
			writeResponse(w, r, response)
			return
		}
		creationTime := time.Unix(int64(binary.BigEndian.Uint64(resetToken[:8])), 0)
		if time.Now().Sub(creationTime) > 24*time.Hour {
			response.Error = "InvalidResetToken"
			writeResponse(w, r, response)
			return
		}
		checksum := blake2b.Sum256(resetToken[8:])
		var resetTokenHash [8 + blake2b.Size256]byte
		copy(resetTokenHash[:8], resetToken[:8])
		copy(resetTokenHash[8:], checksum[:])
		exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT 1 FROM users WHERE reset_token_hash = {resetTokenHash}",
			Values: []any{
				sq.BytesParam("resetTokenHash", resetTokenHash[:]),
			},
		})
		if err != nil {
			GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		if !exists {
			response.Error = "InvalidResetToken"
			writeResponse(w, r, response)
			return
		}
		// password
		if request.Password == "" {
			response.FormErrors.Add("password", "required")
		} else {
			if utf8.RuneCountInString(request.Password) < 8 {
				response.FormErrors.Add("password", "password must be at least 8 characters")
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
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
		if err != nil {
			GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		tx, err := nbrew.DB.Begin()
		if err != nil {
			GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		defer tx.Rollback()
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "DELETE FROM authentication WHERE EXISTS (" +
				"SELECT 1 FROM users WHERE users.user_id = authentication.user_id AND users.reset_token_hash = {resetTokenHash}" +
				")",
			Values: []any{
				sq.BytesParam("resetTokenHash", resetTokenHash[:]),
			},
		})
		if err != nil {
			GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "UPDATE users SET password_hash = {passwordHash}, reset_token_hash = NULL WHERE reset_token_hash = {resetTokenHash}",
			Values: []any{
				sq.StringParam("passwordHash", string(passwordHash)),
				sq.BytesParam("resetTokenHash", resetTokenHash[:]),
			},
		})
		if err != nil {
			GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		err = tx.Commit()
		if err != nil {
			GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		writeResponse(w, r, response)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
