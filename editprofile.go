package nb10

import (
	"encoding/json"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strings"

	"github.com/bokwoon95/nb10/sq"
)

func (nbrew *Notebrew) editprofile(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	type Response struct {
		UserID        ID         `json:"userID"`
		Username      string     `json:"username"`
		DisableReason string     `json:"disableReason"`
		Email         string     `json:"email"`
		Error         string     `json:"error"`
		FormErrors    url.Values `json:"formErrors"`
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
			referer := nbrew.GetReferer(r)
			funcMap := map[string]any{
				"join":       path.Join,
				"hasPrefix":  strings.HasPrefix,
				"trimPrefix": strings.TrimPrefix,
				"contains":   strings.Contains,
				"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
				"baselineJS": func() template.JS { return template.JS(BaselineJS) },
				"referer":    func() string { return referer },
			}
			tmpl, err := template.New("editprofile.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/editprofile.html")
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
		response.UserID = user.UserID
		response.Username = user.Username
		response.DisableReason = user.DisableReason
		response.Email = user.Email
		if response.Error != "" {
			writeResponse(w, r, response)
			return
		}
		writeResponse(w, r, response)
	case "POST":
		if user.DisableReason != "" {
			nbrew.AccountDisabled(w, r, user.DisableReason)
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
				http.Redirect(w, r, "/users/editprofile/", http.StatusFound)
				return
			}
			err := nbrew.SetSession(w, r, "flash", map[string]any{
				"postRedirectGet": map[string]any{
					"from": "editprofile",
				},
			})
			if err != nil {
				GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, "/users/profile/", http.StatusFound)
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
			request.Username = r.Form.Get("username")
			request.Email = r.Form.Get("email")
		default:
			nbrew.UnsupportedContentType(w, r)
			return
		}

		response := Response{
			UserID:     user.UserID,
			Username:   strings.TrimSpace(request.Username),
			Email:      strings.TrimSpace(request.Email),
			FormErrors: url.Values{},
		}
		// username
		if user.Username == "" {
			if response.Username != "" {
				response.FormErrors.Add("username", "cannot change default user's username")
			}
		} else {
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
				if len(response.Username) > 30 {
					response.FormErrors.Add("username", "cannot exceed 30 characters")
				}
			}
		}
		if !response.FormErrors.Has("username") && user.Username != response.Username {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM users WHERE username = {username}",
				Values: []any{
					sq.StringParam("username", response.Username),
				},
			})
			if err != nil {
				GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
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
		if !response.FormErrors.Has("email") && user.Email != response.Email {
			exists, err := sq.FetchExists(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM users WHERE email = {email}",
				Values: []any{
					sq.StringParam("email", response.Email),
				},
			})
			if err != nil {
				GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			if exists {
				response.FormErrors.Add("email", "email already used by an existing user account")
			}
		}
		if len(response.FormErrors) > 0 {
			response.Error = "FormErrorsPresent"
			writeResponse(w, r, response)
			return
		}
		if response.Username == user.Username && response.Email == user.Email {
			writeResponse(w, r, response)
			return
		}
		if user.Username == response.Username || user.Username == "" {
			_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "UPDATE users SET email = {email} WHERE user_id = {userID}",
				Values: []any{
					sq.StringParam("email", response.Email),
					sq.UUIDParam("userID", user.UserID),
				},
			})
			if err != nil {
				GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			writeResponse(w, r, response)
			return
		}
		if user.Email == response.Email {
			_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "UPDATE users SET username = {username} WHERE user_id = {userID}",
				Values: []any{
					sq.StringParam("username", response.Username),
					sq.UUIDParam("userID", user.UserID),
				},
			})
			if err != nil {
				GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
			writeResponse(w, r, response)
			return
		}
		_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "UPDATE users SET username = {username}, email = {email} WHERE user_id = {userID}",
			Values: []any{
				sq.StringParam("username", response.Username),
				sq.StringParam("email", response.Email),
				sq.UUIDParam("userID", user.UserID),
			},
		})
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
