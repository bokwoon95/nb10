package nb10

import (
	"net/http"
	"net/url"
)

func (nbrew *Notebrew) login(w http.ResponseWriter, r *http.Request) {
	type Request struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		CaptchaResponse string `json:"captchaResponse"`
	}
	type Response struct {
		Username            string     `json:"username"`
		RequireCaptcha      bool       `json:"requireCaptcha"`
		CaptchaSiteKey      string     `json:"captchaSiteKey"`
		FormErrors          url.Values `json:"formErrors"`
		AuthenticationToken string     `json:"authenticationToken,omitempty"`
	}
}
