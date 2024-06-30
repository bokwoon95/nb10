package nb10

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strings"
	texttemplate "text/template"
	"unicode/utf8"

	"github.com/bokwoon95/nb10/sq"
	"github.com/caddyserver/certmagic"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/errgroup"
)

func (nbrew *Notebrew) resetpassword(w http.ResponseWriter, r *http.Request) {
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
			tmpl, err := template.New("resetpassword.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/resetpassword.html")
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
				sq.BytesParam("inviteTokenHash", resetTokenHash[:]),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
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
					"from": "invite",
				},
				"username": response.Username,
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
		// token
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
		inviteToken, err := hex.DecodeString(fmt.Sprintf("%048s", response.Token))
		if err != nil {
			response.Error = "InvalidResetToken"
			writeResponse(w, r, response)
			return
		}
		checksum := blake2b.Sum256(inviteToken[8:])
		var inviteTokenHash [8 + blake2b.Size256]byte
		copy(inviteTokenHash[:8], inviteToken[:8])
		copy(inviteTokenHash[8:], checksum[:])
		result, err := sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT {*} FROM invite WHERE invite_token_hash = {inviteTokenHash}",
			Values: []any{
				sq.BytesParam("inviteTokenHash", inviteTokenHash[:]),
			},
		}, func(row *sq.Row) (result struct {
			SiteLimit    sql.NullInt64
			StorageLimit sql.NullInt64
		}) {
			result.SiteLimit = row.NullInt64("site_limit")
			result.StorageLimit = row.NullInt64("storage_limit")
			return result
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				response.Error = "InvalidResetToken"
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
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
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
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
		tx, err := nbrew.DB.Begin()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		defer tx.Rollback()
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "DELETE FROM invite WHERE invite_token_hash = {inviteTokenHash}",
			Values: []any{
				sq.BytesParam("inviteTokenHash", inviteTokenHash[:]),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO site (site_id, site_name)" +
				" VALUES ({siteID}, {siteName})",
			Values: []any{
				sq.UUIDParam("siteID", NewID()),
				sq.StringParam("siteName", response.SiteName),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO users (user_id, username, email, password_hash, site_limit, storage_limit)" +
				" VALUES ({userID}, {username}, {email}, {passwordHash}, {siteLimit}, {storageLimit})",
			Values: []any{
				sq.UUIDParam("userID", NewID()),
				sq.StringParam("username", response.Username),
				sq.StringParam("email", response.Email),
				sq.StringParam("passwordHash", string(passwordHash)),
				sq.Param("siteLimit", result.SiteLimit),
				sq.Param("storageLimit", result.StorageLimit),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO site_user (site_id, user_id)" +
				" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), (SELECT user_id FROM users WHERE username = {username}))",
			Values: []any{
				sq.StringParam("siteName", response.SiteName),
				sq.StringParam("username", response.Username),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		_, err = sq.Exec(r.Context(), tx, sq.Query{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO site_owner (site_id, user_id)" +
				" VALUES ((SELECT site_id FROM site WHERE site_name = {siteName}), (SELECT user_id FROM users WHERE username = {username}))",
			Values: []any{
				sq.StringParam("siteName", response.SiteName),
				sq.StringParam("username", response.Username),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		err = tx.Commit()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		sitePrefix := "@" + response.SiteName
		err = nbrew.FS.Mkdir(sitePrefix, 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		dirs := []string{
			"notes",
			"pages",
			"posts",
			"output",
			"output/posts",
			"output/themes",
			"imports",
			"exports",
		}
		for _, dir := range dirs {
			err = nbrew.FS.Mkdir(path.Join(sitePrefix, dir), 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		}
		var home string
		if response.SiteName == "" {
			home = "home"
		} else if strings.Contains(response.SiteName, ".") {
			home = response.SiteName
		} else {
			home = response.SiteName + "." + nbrew.ContentDomain
		}
		tmpl, err := texttemplate.ParseFS(RuntimeFS, "embed/site.json")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		writer, err := nbrew.FS.WithContext(r.Context()).OpenWriter(path.Join(sitePrefix, "site.json"), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		defer writer.Close()
		err = tmpl.Execute(writer, home)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		err = writer.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		siteGen, err := NewSiteGenerator(r.Context(), SiteGeneratorConfig{
			FS:                 nbrew.FS,
			ContentDomain:      nbrew.ContentDomain,
			ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
			ImgDomain:          nbrew.ImgDomain,
			SitePrefix:         sitePrefix,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		group, groupctx := errgroup.WithContext(r.Context())
		group.Go(func() error {
			b, err := fs.ReadFile(RuntimeFS, "embed/postlist.json")
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/postlist.json"), 0644)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		group.Go(func() error {
			b, err := fs.ReadFile(RuntimeFS, "embed/index.html")
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/index.html"), 0644)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			err = siteGen.GeneratePage(groupctx, "pages/index.html", string(b))
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		group.Go(func() error {
			b, err := fs.ReadFile(RuntimeFS, "embed/404.html")
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/404.html"), 0644)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			err = siteGen.GeneratePage(groupctx, "pages/404.html", string(b))
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		group.Go(func() error {
			b, err := fs.ReadFile(RuntimeFS, "embed/post.html")
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/post.html"), 0644)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		group.Go(func() error {
			b, err := fs.ReadFile(RuntimeFS, "embed/postlist.html")
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			writer, err := nbrew.FS.OpenWriter(path.Join(sitePrefix, "posts/postlist.html"), 0644)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			defer writer.Close()
			_, err = writer.Write(b)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			err = writer.Close()
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			tmpl, err := siteGen.PostListTemplate(context.Background(), "")
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			_, err = siteGen.GeneratePostList(context.Background(), "", tmpl)
			if err != nil {
				getLogger(groupctx).Error(err.Error())
				return nil
			}
			return nil
		})
		err = group.Wait()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		if strings.Contains(response.SiteName, ".") && nbrew.Port == 443 {
			certConfig := certmagic.NewDefault()
			certConfig.Storage = nbrew.CertStorage
			err := certConfig.ObtainCertAsync(r.Context(), response.SiteName)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				nbrew.internalServerError(w, r, err)
				return
			}
		}
		writeResponse(w, r, response)
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
