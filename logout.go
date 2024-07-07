package nb10

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) logout(w http.ResponseWriter, r *http.Request, user User) {
	if user.UserID.IsZero() {
		http.Redirect(w, r, "/users/login/", http.StatusFound)
		return
	}
	var authenticationTokenString string
	header := r.Header.Get("Authorization")
	if header != "" {
		if strings.HasPrefix(header, "Notebrew ") {
			authenticationTokenString = strings.TrimPrefix(header, "Notebrew ")
		}
	} else {
		cookie, _ := r.Cookie("authentication")
		if cookie != nil {
			authenticationTokenString = cookie.Value
		}
	}
	if authenticationTokenString == "" {
		http.Redirect(w, r, "/users/login/", http.StatusFound)
		return
	}
	authenticationToken, err := hex.DecodeString(fmt.Sprintf("%048s", authenticationTokenString))
	if err != nil || len(authenticationToken) != 24 {
		http.Redirect(w, r, "/users/login/", http.StatusFound)
		return
	}
	var authenticationTokenHash [8 + blake2b.Size256]byte
	checksum := blake2b.Sum256(authenticationToken[8:])
	copy(authenticationTokenHash[:8], authenticationToken[:8])
	copy(authenticationTokenHash[8:], checksum[:])
	switch r.Method {
	case "GET", "HEAD":
		funcMap := map[string]any{
			"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
			"baselineJS": func() template.JS { return template.JS(BaselineJS) },
			"referer":    func() string { return r.Referer() },
		}
		tmpl, err := template.New("logout.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/logout.html")
		if err != nil {
			GetLogger(r.Context()).Error(err.Error())
			nbrew.InternalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.ExecuteTemplate(w, r, tmpl, nil)
	case "POST":
		http.SetCookie(w, &http.Cookie{
			Path:   "/",
			Name:   "authentication",
			Value:  "0",
			MaxAge: -1,
		})
		if authenticationTokenHash != [len(authenticationTokenHash)]byte{} {
			_, err := sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "DELETE FROM authentication WHERE authentication_token_hash = {authenticationTokenHash}",
				Values: []any{
					sq.BytesParam("authenticationTokenHash", authenticationTokenHash[:]),
				},
			})
			if err != nil {
				GetLogger(r.Context()).Error(err.Error())
				nbrew.InternalServerError(w, r, err)
				return
			}
		}
		http.Redirect(w, r, "/users/login/", http.StatusFound)
	default:
		nbrew.MethodNotAllowed(w, r)
	}
}
