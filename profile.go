package nb10

import (
	"encoding/json"
	"html/template"
	"net/http"
	"path"
	"strings"

	"github.com/bokwoon95/nb10/sq"
)

// TODO: in profile we can show the site memory usage as well!
// Per-site storage usage as well as overall total storage usage
// out of the total available storage that the user has. Then we
// can move storage used out of site.json.
func (nbrew *Notebrew) profile(w http.ResponseWriter, r *http.Request, user User) {
	type Site struct {
		SiteID      ID     `json:"siteID"`
		SiteName    string `json:"siteName"`
		StorageUsed int64  `json:"storageUsed"`
	}
	type Response struct {
		IsDatabaseFS  bool   `json:"isDatabaseFS"`
		UserID        ID     `json:"userID"`
		Username      string `json:"username"`
		Email         string `json:"email"`
		DisableReason string `json:"disableReason"`
		SiteLimit     int64  `json:"siteLimit"`
		StorageLimit  int64  `json:"storageLimit"`
		StorageUsed   int64  `json:"storageUsed"`
		Sites         []Site `json:"sites"`
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		nbrew.methodNotAllowed(w, r)
		return
	}
	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if r.Form.Has("api") {
			w.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(w)
			encoder.SetIndent("", "  ")
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(&response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
			}
			return
		}
		referer := nbrew.getReferer(r)
		funcMap := map[string]any{
			"join":                  path.Join,
			"dir":                   path.Dir,
			"base":                  path.Base,
			"ext":                   path.Ext,
			"hasPrefix":             strings.HasPrefix,
			"hasSuffix":             strings.HasSuffix,
			"trimPrefix":            strings.TrimPrefix,
			"trimSuffix":            strings.TrimSuffix,
			"humanReadableFileSize": humanReadableFileSize,
			"stylesCSS":             func() template.CSS { return template.CSS(StylesCSS) },
			"baselineJS":            func() template.JS { return template.JS(BaselineJS) },
			"referer":               func() string { return referer },
			"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
			"float64ToInt64":        func(n float64) int64 { return int64(n) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
			"toSitePrefix": func(siteName string) string {
				if strings.Contains(siteName, ".") {
					return siteName
				}
				return "@" + siteName
			},
		}
		tmpl, err := template.New("profile.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/profile.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.executeTemplate(w, r, tmpl, &response)
	}
	response := Response{
		UserID:        user.UserID,
		Username:      user.Username,
		Email:         user.Email,
		DisableReason: user.DisableReason,
		SiteLimit:     user.SiteLimit,
		StorageLimit:  user.StorageLimit,
	}
	sites, err := sq.FetchAll(r.Context(), nbrew.DB, sq.Query{
		Dialect: nbrew.Dialect,
		Format: "SELECT {*}" +
			" FROM site" +
			" JOIN site_owner ON site_owner.site_id = site.site_id" +
			" WHERE site_owner.user_id = {userID}",
		Values: []any{
			sq.UUIDParam("userID", user.UserID),
		},
	}, func(row *sq.Row) Site {
		return Site{
			SiteID:      row.UUID("site.site_id"),
			SiteName:    row.String("site.site_name"),
			StorageUsed: row.Int64("site.storage_used"),
		}
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}
	response.Sites = sites
	_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
	if response.IsDatabaseFS {
		for _, site := range response.Sites {
			response.StorageUsed += site.StorageUsed
		}
	}
	writeResponse(w, r, response)
}
