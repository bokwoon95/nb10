package nb10

import (
	"net/http"
	"time"
)

func (nbrew *Notebrew) cancelexports(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type ExportJob struct {
		ExportJobID    ID        `json:"exportJobID"`
		FileName       string    `json:"fileName"`
		StartTime      time.Time `json:"startTime"`
		TotalBytes     int64     `json:"totalBytes"`
		ProcessedBytes int64     `json:"processedBytes"`
	}
	type Request struct {
		ExportJobIDs []ID `json:"exportJobIDs"`
	}
	type Response struct {
		ContentBaseURL string      `json:"contentBaseURL"`
		ImgDomain      string      `json:"imgDomain"`
		IsDatabaseFS   bool        `json:"isDatabaseFS"`
		SitePrefix     string      `json:"sitePrefix"`
		UserID         ID          `json:"userID"`
		Username       string      `json:"username"`
		ExportJobs     []ExportJob `json:"exportJobs"`
	}

	switch r.Method {
	case "GET":
	case "POST":
	default:
		nbrew.methodNotAllowed(w, r)
	}
}
