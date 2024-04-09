package nb10

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/bokwoon95/nb10/sq"
)

func (nbrew *Notebrew) search(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Match struct {
		FileID       ID        `json:"fileID"`
		FilePath     string    `json:"filePath"`
		Preview      string    `json:"preview"`
		CreationTime time.Time `json:"creationTime"`
	}
	type Request struct {
		Parent   string   `json:"parent"`
		Query    string   `json:"query"`
		Operator string   `json:"operator"`
		Exts     []string `json:"exts"`
	}
	type Response struct {
		ContentBaseURL string   `json:"contentBaseURL"`
		SitePrefix     string   `json:"sitePrefix"`
		ImgDomain      string   `json:"imgDomain"`
		IsDatabaseFS   bool     `json:"isDatabaseFS"`
		UserID         ID       `json:"userID"`
		Username       string   `json:"username"`
		Parent         string   `json:"parent"`
		Query          string   `json:"query"`
		Operator       string   `json:"operator"`
		Exts           []string `json:"exts"`
		Matches        []Match  `json:"matches"`
	}

	isValidParent := func(parent string) bool {
		if !fs.ValidPath(parent) || strings.Contains(parent, "\\") {
			return false
		}
		if parent == "." {
			return true
		}
		head, _, _ := strings.Cut(parent, "/")
		switch head {
		case "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, parent))
			if err != nil {
				return false
			}
			if fileInfo.IsDir() {
				return true
			}
		}
		return false
	}

	if r.Method != "GET" {
		nbrew.methodNotAllowed(w, r)
		return
	}

	databaseFS, ok := nbrew.FS.(*DatabaseFS)
	if !ok {
		nbrew.notFound(w, r)
		return
	}

	writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
		if r.Form.Has("api") {
			w.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(w)
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(&response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
			}
			return
		}
		referer := nbrew.getReferer(r)
		extMap := make(map[string]struct{})
		for _, ext := range response.Exts {
			extMap[ext] = struct{}{}
		}
		funcMap := map[string]any{
			"join":       path.Join,
			"dir":        path.Dir,
			"base":       path.Base,
			"ext":        path.Ext,
			"hasPrefix":  strings.HasPrefix,
			"trimPrefix": strings.TrimPrefix,
			"contains":   strings.Contains,
			"stylesCSS":  func() template.CSS { return template.CSS(StylesCSS) },
			"baselineJS": func() template.JS { return template.JS(BaselineJS) },
			"referer":    func() string { return referer },
			"incr":       func(n int) int { return n + 1 },
			"hasExt": func(ext string) bool {
				_, ok := extMap[ext]
				return ok
			},
		}
		tmpl, err := template.New("search.html").Funcs(funcMap).ParseFS(RuntimeFS, "embed/search.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
		w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
		nbrew.executeTemplate(w, r, tmpl, &response)
	}

	request := Request{
		Parent:   r.Form.Get("parent"),
		Query:    r.Form.Get("query"),
		Operator: r.Form.Get("operator"),
		Exts:     r.Form["ext"],
	}

	var response Response
	response.ContentBaseURL = nbrew.contentBaseURL(sitePrefix)
	response.ImgDomain = nbrew.ImgDomain
	_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
	response.SitePrefix = sitePrefix
	response.UserID = user.UserID
	response.Username = user.Username
	response.Parent = path.Clean(strings.Trim(request.Parent, "/"))
	response.Query = strings.TrimSpace(request.Query)
	response.Operator = strings.ToLower(strings.TrimSpace(request.Operator))
	if response.Operator != "or" && response.Operator != "and" {
		response.Operator = "or"
	}
	if len(request.Exts) > 0 {
		for _, ext := range request.Exts {
			switch ext {
			case ".html", ".css", ".js", ".md", ".txt", ".json",
				".jpeg", ".jpg", ".png", ".webp", ".gif":
				response.Exts = append(response.Exts, ext)
			}
		}
		slices.Sort(response.Exts)
		response.Exts = slices.Compact(response.Exts)
	}
	if !isValidParent(response.Parent) {
		response.Parent = "."
	}
	if response.Query == "" {
		writeResponse(w, r, response)
		return
	}
	var err error
	switch databaseFS.Dialect {
	case "sqlite":
		var parentFilter sq.Expression
		parent := path.Join(sitePrefix, response.Parent)
		if parent == "." {
			parentFilter = sq.Expr("(file_path LIKE 'notes/%'" +
				" OR file_path LIKE 'pages/%'" +
				" OR file_path LIKE 'posts/%'" +
				" OR file_path LIKE 'output/%'" +
				" OR parent_id IS NULL)")
		} else {
			parentFilter = sq.Expr("file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(parent)+"/%")
		}
		extensionFilter := sq.Expr("1 = 1")
		if len(response.Exts) > 0 {
			var b strings.Builder
			var args []any
			b.WriteString("(")
			for i, ext := range response.Exts {
				if i > 0 {
					b.WriteString(" OR ")
				}
				b.WriteString("file_path LIKE {}")
				args = append(args, "%"+ext)
			}
			b.WriteString(")")
			extensionFilter = sq.Expr(b.String(), args...)
		}
		response.Matches, err = sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
			Debug:   true,
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" JOIN files_fts5 ON files_fts5.rowid = files.rowid" +
				" WHERE {parentFilter}" +
				" AND files_fts5 MATCH {query}" +
				" AND {extensionFilter}" +
				" ORDER BY files_fts5.rank, files.creation_time DESC",
			Values: []any{
				sq.Param("parentFilter", parentFilter),
				sq.StringParam("query", `"`+strings.ReplaceAll(response.Query, `"`, `""`)+`"`),
				sq.Param("extensionFilter", extensionFilter),
			},
		}, func(row *sq.Row) Match {
			match := Match{
				FileID:       row.UUID("files.file_id"),
				FilePath:     row.String("files.file_path"),
				Preview:      row.String("CASE WHEN files.file_path LIKE '%.json' THEN '' ELSE substr(files.text, 1, 500) END"),
				CreationTime: row.Time("files.creation_time"),
			}
			if sitePrefix != "" {
				_, match.FilePath, _ = strings.Cut(match.FilePath, "/")
			}
			return match
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			nbrew.internalServerError(w, r, err)
			return
		}
	case "postgres":
	case "mysql":
	}
	writeResponse(w, r, response)
}
