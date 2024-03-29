package nb10

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

func (nbrew *Notebrew) pin(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type File struct {
		FileID  ID        `json:"fileID"`
		Name    string    `json:"name"`
		IsDir   bool      `json:"isDir"`
		Size    int64     `json:"size"`
		ModTime time.Time `json:"modTime"`
	}
	type Request struct {
		Unpin  bool     `json:"unpin"`
		Parent string   `json:"parent"`
		Names  []string `json:"names"`
	}
	type Response struct {
		ContentBaseURL string `json:"contentBaseURL"`
		ImgDomain      string `json:"imgDomain"`
		IsDatabaseFS   bool   `json:"isDatabaseFS"`
		SitePrefix     string `json:"sitePrefix"`
		UserID         ID     `json:"userID"`
		Username       string `json:"username"`
		Unpin          bool   `json:"unpin"`
		Parent         string `json:"parent"`
		Files          []File `json:"files"`
		Error          string `json:"status"`
	}
	if r.Method != "POST" {
		nbrew.methodNotAllowed(w, r)
		return
	}

	isValidParent := func(parent string) bool {
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
	_ = isValidParent
}
