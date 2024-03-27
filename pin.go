package nb10

import (
	"net/http"
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
		Parent         string `json:"parent"`
		Files          []File `json:"files"`
		Error          string `json:"status"`
	}
}
