package nb10

import "net/http"

func (nbrew *Notebrew) resettheme(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Request struct {
		ResetAllCategories bool
		Category           string
	}
	type Response struct {
		ContentBaseURL string   `json:"contentBaseURL"`
		IsDatabaseFS   bool     `json:"isDatabaseFS"`
		SitePrefix     string   `json:"sitePrefix"`
		UserID         ID       `json:"userID"`
		Username       string   `json:"username"`
		DisableReason  string   `json:"disableReason"`
		Categories     []string `json:"categories"`
	}
}
