package nb10

import (
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
)

func (nbrew *Notebrew) pin(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
	type Response struct {
		Parent    string   `json:"parent"`
		NumPinned int      `json:"numPinned"`
		Names     []string `json:"names"`
	}
	if r.Method != "POST" {
		nbrew.methodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20 /* 1 MB */)
	err := r.ParseForm()
	if err != nil {
		nbrew.badRequest(w, r, err)
		return
	}
	referer := r.Referer()
	if referer == "" {
		http.Redirect(w, r, "/"+path.Join("files", sitePrefix)+"/", http.StatusFound)
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

	parent := path.Clean(strings.Trim(r.Form.Get("parent"), "/"))
	if !isValidParent(parent) {
		http.Redirect(w, r, referer, http.StatusFound)
		return
	}
	names := r.Form["name"]
	if len(names) == 0 {
		http.Redirect(w, r, referer, http.StatusFound)
		return
	}
	slices.Sort(names)
	names = slices.Compact(names)
	response := Response{}
	_ = response
}

func (nbrew *Notebrew) unpin(w http.ResponseWriter, r *http.Request, user User, sitePrefix string) {
}
