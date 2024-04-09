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
	"unicode"
	"unicode/utf8"

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
		Parent      string   `json:"parent"`
		SearchTerms string   `json:"searchTerms"`
		Operator    string   `json:"operator"`
		Exts        []string `json:"exts"`
	}
	type Response struct {
		ContentBaseURL string   `json:"contentBaseURL"`
		SitePrefix     string   `json:"sitePrefix"`
		ImgDomain      string   `json:"imgDomain"`
		IsDatabaseFS   bool     `json:"isDatabaseFS"`
		UserID         ID       `json:"userID"`
		Username       string   `json:"username"`
		Parent         string   `json:"parent"`
		SearchTerms    string   `json:"searchTerms"`
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
		Parent:      r.Form.Get("parent"),
		SearchTerms: r.Form.Get("searchTerms"),
		Operator:    r.Form.Get("operator"),
		Exts:        r.Form["ext"],
	}

	var response Response
	response.ContentBaseURL = nbrew.contentBaseURL(sitePrefix)
	response.ImgDomain = nbrew.ImgDomain
	_, response.IsDatabaseFS = nbrew.FS.(*DatabaseFS)
	response.SitePrefix = sitePrefix
	response.UserID = user.UserID
	response.Username = user.Username
	response.Parent = path.Clean(strings.Trim(request.Parent, "/"))
	response.SearchTerms = strings.TrimSpace(request.SearchTerms)
	response.Operator = strings.ToUpper(strings.TrimSpace(request.Operator))
	if response.Operator != "OR" && response.Operator != "AND" {
		response.Operator = "OR"
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
	var includeTerms []string
	var excludeTerms []string
	exclude := false
	inString := false
	var b strings.Builder
	for i, char := range response.SearchTerms {
		if char == '"' {
			if b.Len() > 0 {
				if exclude {
					excludeTerms = append(excludeTerms, b.String())
				} else {
					includeTerms = append(includeTerms, b.String())
				}
				exclude = false
				b.Reset()
			}
			inString = !inString
			continue
		}
		if inString {
			b.WriteRune(char)
			continue
		}
		if b.Len() == 0 {
			if unicode.IsSpace(char) {
				continue
			}
			if char == '-' {
				nextChar, _ := utf8.DecodeRuneInString(response.SearchTerms[i+1:])
				if nextChar != utf8.RuneError && !unicode.IsSpace(nextChar) {
					exclude = true
				}
				continue
			}
			b.WriteRune(char)
			continue
		}
		if unicode.IsSpace(char) {
			if exclude {
				excludeTerms = append(excludeTerms, b.String())
			} else {
				includeTerms = append(includeTerms, b.String())
			}
			exclude = false
			b.Reset()
			continue
		}
		b.WriteRune(char)
	}
	if b.Len() > 0 {
		if exclude {
			excludeTerms = append(excludeTerms, b.String())
		} else {
			includeTerms = append(includeTerms, b.String())
		}
	}
	if len(includeTerms) == 0 && len(excludeTerms) == 0 {
		writeResponse(w, r, response)
		return
	}
	var err error
	var parentFilter sq.Expression
	parent := path.Join(sitePrefix, response.Parent)
	if parent == "." {
		parentFilter = sq.Expr("(files.file_path LIKE 'notes/%'" +
			" OR files.file_path LIKE 'pages/%'" +
			" OR files.file_path LIKE 'posts/%'" +
			" OR files.file_path LIKE 'output/%'" +
			" OR files.parent_id IS NULL)")
	} else {
		parentFilter = sq.Expr("files.file_path LIKE {} ESCAPE '\\'", wildcardReplacer.Replace(parent)+"/%")
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
			b.WriteString("files.file_path LIKE {}")
			args = append(args, "%"+ext)
		}
		b.WriteString(")")
		extensionFilter = sq.Expr(b.String(), args...)
	}
	switch databaseFS.Dialect {
	case "sqlite":
		var b strings.Builder
		if len(excludeTerms) > 0 {
			b.WriteString("(")
		}
		if len(includeTerms) == 0 {
			includeTerms = []string{""}
		}
		for i, term := range includeTerms {
			if i > 0 {
				b.WriteString(" " + response.Operator + " ")
			}
			b.WriteString(`"` + strings.ReplaceAll(term, `"`, `""`) + `"`)
		}
		if len(excludeTerms) > 0 {
			b.WriteString(")")
			for _, term := range excludeTerms {
				b.WriteString(" NOT " + `"` + strings.ReplaceAll(term, `"`, `""`) + `"`)
			}
		}
		ftsQuery := b.String()
		response.Matches, err = sq.FetchAll(r.Context(), databaseFS.DB, sq.Query{
			Debug:   true,
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" JOIN files_fts5 ON files_fts5.rowid = files.rowid" +
				" WHERE {parentFilter}" +
				" AND files_fts5 MATCH {ftsQuery}" +
				" AND {extensionFilter}" +
				" ORDER BY files_fts5.rank, files.creation_time DESC",
			Values: []any{
				sq.Param("parentFilter", parentFilter),
				sq.StringParam("ftsQuery", ftsQuery),
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
