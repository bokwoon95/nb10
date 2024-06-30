package nb10

import "net/http"

func (nbrew *Notebrew) editprofile(w http.ResponseWriter, r *http.Request, user User) {
	type Response struct {
		IsDatabaseFS    bool           `json:"isDatabaseFS"`
		UserID          ID             `json:"userID"`
		Username        string         `json:"username"`
		Email           string         `json:"email"`
		DisableReason   string         `json:"disableReason"`
		SiteLimit       int64          `json:"siteLimit"`
		StorageLimit    int64          `json:"storageLimit"`
		StorageUsed     int64          `json:"storageUsed"`
		Sites           []Site         `json:"sites"`
		PostRedirectGet map[string]any `json:"postRedirectGet"`
	}
}
