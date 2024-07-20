package nb10

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (nbrew *Notebrew) updateemail(w http.ResponseWriter, r *http.Request, user User) {
	type Request struct {
		Password string `json:"password"`
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
					getLogger(r.Context()).Error(err.Error())
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
			tmpl, err := template.New("updateemail.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/updateemail.html")
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
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
