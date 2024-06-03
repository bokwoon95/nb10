package nb10

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bokwoon95/nb10/sq"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
	"golang.org/x/crypto/blake2b"
)

var (
	//go:embed embed static
	embedFS embed.FS

	RuntimeFS fs.FS = embedFS

	devMode = false

	StylesCSS string

	StylesCSSHash string

	BaselineJS string

	BaselineJSHash string

	contentSecurityPolicy string

	contentSecurityPolicyWithCaptcha string
)

func init() {
	// styles.css
	b, err := fs.ReadFile(embedFS, "static/styles.css")
	if err != nil {
		return
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	hash := sha256.Sum256(b)
	StylesCSS = string(b)
	StylesCSSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
	// baseline.js
	b, err = fs.ReadFile(embedFS, "static/baseline.js")
	if err != nil {
		return
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	hash = sha256.Sum256(b)
	BaselineJS = string(b)
	BaselineJSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
}

// totalBytes/processedBytes
// writers always write to the job struct. every 1 MB, persist the job struct to the database
// readers always read from the database if it exists, else they read from the jobs map

// the problem with queueing is that it becomes possible to queue on one machine and cancel on another. it's fine and dandy if you have a database, but what if you don't? What if you only have the map?
// solution: if you push job, if database is present then add to the database (but not the map). if no database, then add it to the map. if you pop job, if database is present then select skip locked
// 1. jobs need to update the processedBytes every max(1 MB, 1%)
type job struct {
	sitePrefix     string
	fileName       string
	status         string // queued | started | completed | cancelled | restart
	totalBytes     int64
	processedBytes int64
	syncThreshold  int64
	startTime      time.Time
	cancel         func()
	done           chan struct{}
}

// Notebrew represents a notebrew instance.
type Notebrew struct {
	CMSDomain string // localhost:6444, example.com

	CMSDomainHTTPS bool

	ContentDomain string // localhost:6444, example.com

	ContentDomainHTTPS bool

	ImgDomain string

	ImgCmd string

	Port int

	IP4 netip.Addr

	IP6 netip.Addr

	Domains []string

	ManagingDomains []string

	// FS is the file system associated with the notebrew instance.
	FS FS

	// DB is the DB associated with the notebrew instance.
	DB *sql.DB

	// Dialect is Dialect of the database. Only sqlite, postgres and mysql
	// databases are supported.
	Dialect string

	// ErrorCode translates a database error into an dialect-specific error
	// code. If the error is not a database error or if no underlying
	// implementation is provided, ErrorCode should return an empty string.
	ErrorCode func(error) string

	ctx       context.Context
	cancel    func()
	waitGroup sync.WaitGroup

	CaptchaConfig struct {
		WidgetScriptSrc template.URL
		WidgetClass     string
		VerificationURL string
		SiteKey         string
		SecretKey       string
		CSP             map[string]string
	}

	ProxyConfig struct {
		RealIPHeaders map[netip.Addr]string
		ProxyIPs      map[netip.Addr]struct{}
	}

	DNSProvider interface {
		libdns.RecordAppender
		libdns.RecordDeleter
		libdns.RecordGetter
		libdns.RecordSetter
	}

	CertStorage certmagic.Storage

	ContentSecurityPolicy string

	Logger *slog.Logger
}

func New() *Notebrew {
	ctx, cancel := context.WithCancel(context.Background())
	nbrew := &Notebrew{
		ctx:    ctx,
		cancel: cancel,
	}
	return nbrew
}

func (nbrew *Notebrew) Close() error {
	nbrew.cancel()
	nbrew.waitGroup.Wait()
	return nil
}

type User struct {
	UserID   ID
	Username string
	// accountDisabled(): "you may not perform that action as your account has been disabled for the following reason"
	DisableReason string
	SiteLimit     int64
	// storageLimitExceeded(): "you have exceeded your storage limit of {{ $storageLimit }} (current: {{ $currentStorage }})"
	StorageLimit int64
}

type contextKey struct{}

var loggerKey = &contextKey{}

func getLogger(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

func (nbrew *Notebrew) setSession(w http.ResponseWriter, r *http.Request, name string, value any) error {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(&value)
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	cookie := &http.Cookie{
		Path:     "/",
		Name:     name,
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if devMode {
		os.Stderr.WriteString(buf.String())
	}
	if nbrew.DB == nil {
		cookie.Value = base64.URLEncoding.EncodeToString(buf.Bytes())
	} else {
		var sessionToken [8 + 16]byte
		binary.BigEndian.PutUint64(sessionToken[:8], uint64(time.Now().Unix()))
		_, err := rand.Read(sessionToken[8:])
		if err != nil {
			return fmt.Errorf("reading rand: %w", err)
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(sessionToken[8:])
		copy(sessionTokenHash[:8], sessionToken[:8])
		copy(sessionTokenHash[8:], checksum[:])
		_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "INSERT INTO session (session_token_hash, data) VALUES ({sessionTokenHash}, {data})",
			Values: []any{
				sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
				sq.StringParam("data", strings.TrimSpace(buf.String())),
			},
		})
		if err != nil {
			return fmt.Errorf("saving session: %w", err)
		}
		cookie.Value = strings.TrimLeft(hex.EncodeToString(sessionToken[:]), "0")
	}
	http.SetCookie(w, cookie)
	return nil
}

func (nbrew *Notebrew) getSession(r *http.Request, name string, valuePtr any) (ok bool, err error) {
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return false, nil
	}
	var data []byte
	if nbrew.DB == nil {
		data, err = base64.URLEncoding.DecodeString(cookie.Value)
		if err != nil {
			return false, nil
		}
	} else {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
		if err != nil {
			return false, nil
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(sessionToken[8:])
		copy(sessionTokenHash[:8], sessionToken[:8])
		copy(sessionTokenHash[8:], checksum[:])
		creationTime := time.Unix(int64(binary.BigEndian.Uint64(sessionTokenHash[:8])), 0)
		if time.Now().Sub(creationTime) > 5*time.Minute {
			return false, nil
		}
		data, err = sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "SELECT {*} FROM session WHERE session_token_hash = {sessionTokenHash}",
			Values: []any{
				sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
			},
		}, func(row *sq.Row) []byte {
			return row.Bytes(nil, "data")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	err = decoder.Decode(valuePtr)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (nbrew *Notebrew) clearSession(w http.ResponseWriter, r *http.Request, name string) {
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Path:     "/",
		Name:     name,
		Value:    "0",
		MaxAge:   -1,
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	if nbrew.DB == nil {
		return
	}
	sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
	if err != nil {
		return
	}
	var sessionTokenHash [8 + blake2b.Size256]byte
	checksum := blake2b.Sum256(sessionToken[8:])
	copy(sessionTokenHash[:8], sessionToken[:8])
	copy(sessionTokenHash[8:], checksum[:])
	_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
		Dialect: nbrew.Dialect,
		Format:  "DELETE FROM session WHERE session_token_hash = {sessionTokenHash}",
		Values: []any{
			sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
		},
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	}
}

var base32Encoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

func stripMarkdownStyles(markdown goldmark.Markdown, src []byte) string {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var node ast.Node
	nodes := []ast.Node{
		markdown.Parser().Parse(text.NewReader(src)),
	}
	for len(nodes) > 0 {
		node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
		if node == nil {
			continue
		}
		switch node := node.(type) {
		case *ast.Text:
			buf.Write(node.Text(src))
		}
		nodes = append(nodes, node.NextSibling(), node.FirstChild())
	}
	// Manually escape backslashes (goldmark may be able to do this,
	// investigate).
	var b strings.Builder
	output := buf.Bytes()
	// Jump to the location of each backslash found in the output.
	for i := bytes.IndexByte(output, '\\'); i >= 0; i = bytes.IndexByte(output, '\\') {
		b.Write(output[:i])
		char, width := utf8.DecodeRune(output[i+1:])
		if char != utf8.RuneError {
			b.WriteRune(char)
		}
		output = output[i+1+width:]
	}
	b.Write(output)
	return b.String()
}

var isURLUnsafe = [...]bool{
	' ': true, '!': true, '"': true, '#': true, '$': true, '%': true, '&': true, '\'': true,
	'(': true, ')': true, '*': true, '+': true, ',': true, '/': true, ':': true, ';': true,
	'<': true, '>': true, '=': true, '?': true, '[': true, ']': true, '\\': true, '^': true,
	'`': true, '{': true, '}': true, '|': true, '~': true,
}

func urlSafe(s string) string {
	s = strings.TrimSpace(s)
	var count int
	var b strings.Builder
	b.Grow(len(s))
	for _, char := range s {
		if count >= 80 {
			break
		}
		if char == ' ' {
			b.WriteRune('-')
			count++
			continue
		}
		if char == '-' || (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') {
			b.WriteRune(char)
			count++
			continue
		}
		if char >= 'A' && char <= 'Z' {
			b.WriteRune(unicode.ToLower(char))
			count++
			continue
		}
		n := int(char)
		if n < len(isURLUnsafe) && isURLUnsafe[n] {
			continue
		}
		b.WriteRune(char)
		count++
	}
	return strings.Trim(b.String(), ".")
}

// https://stackoverflow.com/a/31976060
var isFilenameUnsafe = [...]bool{
	'<': true, '>': true, ':': true, '"': true, '/': true,
	'\\': true, '|': true, '?': true, '*': true,
	'#': true, /* '#' is technically allowed in filenames but plays havoc with URLs, so exclude */
}

func filenameSafe(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, char := range s {
		if char >= 0 && char <= 31 {
			continue
		}
		n := int(char)
		if n < len(isFilenameUnsafe) && isFilenameUnsafe[n] {
			continue
		}
		b.WriteRune(char)
	}
	return strings.Trim(b.String(), ".")
}

var hashPool = sync.Pool{
	New: func() any {
		hash, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return hash
	},
}

var readerPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 512)
	},
}

func (nbrew *Notebrew) executeTemplate(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data any) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()

	hasher := hashPool.Get().(hash.Hash)
	defer func() {
		hasher.Reset()
		hashPool.Put(hasher)
	}()

	multiWriter := io.MultiWriter(buf, hasher)
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(multiWriter)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()

	err := tmpl.Execute(gzipWriter, data)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		fmt.Printf(fmt.Sprintf("%#v", data))
		nbrew.internalServerError(w, r, err)
		return
	}
	err = gzipWriter.Close()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		nbrew.internalServerError(w, r, err)
		return
	}

	var b [blake2b.Size256]byte
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(buf.Bytes()))
}

func (nbrew *Notebrew) contentBaseURL(sitePrefix string) string {
	if strings.Contains(sitePrefix, ".") {
		return "https://" + sitePrefix
	}
	if nbrew.CMSDomainHTTPS {
		if sitePrefix != "" {
			return "https://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.ContentDomain
		}
		return "https://" + nbrew.ContentDomain
	}
	if sitePrefix != "" {
		return "http://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.CMSDomain
	}
	return "http://" + nbrew.CMSDomain
}

func (nbrew *Notebrew) getReferer(r *http.Request) string {
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
	//
	// "The Referer header can contain an origin, path, and querystring, and
	// may not contain URL fragments (i.e. #section) or username:password
	// information."
	referer := r.Referer()
	uri := *r.URL
	if r.TLS == nil {
		uri.Scheme = "http"
	} else {
		uri.Scheme = "https"
	}
	uri.Host = r.Host
	uri.Fragment = ""
	uri.User = nil
	// If the referer is same as the current page, return an empty string so
	// that the user doesn't keep pressing back to the same page.
	if referer == uri.String() {
		return ""
	}
	return referer
}

var errorTemplate = template.Must(template.
	New("error.html").
	Funcs(map[string]any{
		"safeHTML": func(v any) template.HTML {
			if str, ok := v.(string); ok {
				return template.HTML(str)
			}
			return ""
		},
	}).
	ParseFS(RuntimeFS, "embed/error.html"),
)

func humanReadableFileSize(size int64) string {
	// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
	if size < 0 {
		return ""
	}
	const unit = 1000
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "kMGTPE"[exp])
}

func (nbrew *Notebrew) badRequest(w http.ResponseWriter, r *http.Request, serverErr error) {
	var message string
	var maxBytesErr *http.MaxBytesError
	if errors.As(serverErr, &maxBytesErr) {
		message = "the data you are sending is too big (max " + humanReadableFileSize(maxBytesErr.Limit) + ")"
	} else {
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType == "application/json" {
			if serverErr == io.EOF {
				message = "missing JSON body"
			} else if serverErr == io.ErrUnexpectedEOF {
				message = "malformed JSON"
			} else {
				message = serverErr.Error()
			}
		} else {
			message = serverErr.Error()
		}
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "BadRequest",
			"message": message,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    `400 bad request`,
		"Headline": "400 bad request",
		"Byline":   message,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "BadRequest: "+message, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusBadRequest)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

func (nbrew *Notebrew) notAuthenticated(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotAuthenticated",
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var query string
	if r.Method == "GET" {
		if r.URL.RawQuery != "" {
			query = "?redirect=" + url.QueryEscape(r.URL.Path+"?"+r.URL.RawQuery)
		} else {
			query = "?redirect=" + url.QueryEscape(r.URL.Path)
		}
	}
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    "401 unauthorized",
		"Headline": "401 unauthorized",
		"Byline":   fmt.Sprintf("You are not authenticated, please <a href='/users/login/%s'>log in</a>.", query),
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotAuthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusUnauthorized)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

func (nbrew *Notebrew) notAuthorized(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotAuthorized",
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var byline string
	if r.Method == "GET" {
		byline = "You do not have permission to view this page (try logging in to a different account)."
	} else {
		byline = "You do not have permission to perform that action (try logging in to a different account)."
	}
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  nbrew.getReferer(r),
		"Title":    "403 forbidden",
		"Headline": "403 forbidden",
		"Byline":   byline,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotAuthorized", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusForbidden)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

func (nbrew *Notebrew) notFound(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotFound",
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  nbrew.getReferer(r),
		"Title":    "404 not found",
		"Headline": "404 not found",
		"Byline":   "The page you are looking for does not exist.",
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotFound", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusNotFound)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

func (nbrew *Notebrew) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":  "MethodNotAllowed",
			"method": r.Method,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  nbrew.getReferer(r),
		"Title":    "405 method not allowed",
		"Headline": "405 method not allowed: " + r.Method,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotFound", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusMethodNotAllowed)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

func (nbrew *Notebrew) unsupportedContentType(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	var message string
	if contentType == "" {
		message = "missing Content-Type"
	} else {
		message = "unsupported Content-Type: " + contentType
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "UnsupportedMediaType",
			"message": message,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  nbrew.getReferer(r),
		"Title":    "415 unsupported media type",
		"Headline": message,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "UnsupportedMediaType "+message, http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusUnsupportedMediaType)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

func (nbrew *Notebrew) internalServerError(w http.ResponseWriter, r *http.Request, serverErr error) {
	if serverErr == nil {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "InternalServerError",
			"message": serverErr.Error(),
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var data map[string]any
	if errors.Is(serverErr, context.DeadlineExceeded) {
		data = map[string]any{
			"Referer":  nbrew.getReferer(r),
			"Title":    "deadline exceeded",
			"Headline": "The server took too long to process your request.",
		}
	} else {
		data = map[string]any{
			"Referer":  nbrew.getReferer(r),
			"Title":    "500 internal server error",
			"Headline": "500 internal server error",
			"Byline":   "There's a bug with notebrew.",
			"Details":  serverErr.Error(),
		}
	}
	err := errorTemplate.Execute(buf, data)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "ServerError", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusInternalServerError)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

func serveFile(w http.ResponseWriter, r *http.Request, file fs.File, fileInfo fs.FileInfo, fileType FileType, cacheControl string) {
	// If max-age is present in Cache-Control, don't set the ETag because that
	// would override max-age. https://stackoverflow.com/a/51257030
	hasMaxAge := strings.Contains(cacheControl, "max-age=")

	// .jpeg .jpg .png .webp .gif .woff .woff2
	if !fileType.IsGzippable {
		if fileSeeker, ok := file.(io.ReadSeeker); ok {
			if hasMaxAge {
				w.Header().Set("Content-Type", fileType.ContentType)
				w.Header().Set("Cache-Control", cacheControl)
				http.ServeContent(w, r, "", time.Time{}, fileSeeker)
				return
			}
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			_, err := io.Copy(hasher, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			_, err = fileSeeker.Seek(0, io.SeekStart)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			http.ServeContent(w, r, "", time.Time{}, fileSeeker)
			return
		}
		w.Header().Set("Content-Type", fileType.ContentType)
		w.Header().Set("Cache-Control", cacheControl)
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, err := io.Copy(w, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}

	// .html .css .js .md .txt .svg .ico .eot .otf .ttf .atom .json

	if databaseFile, ok := file.(*DatabaseFile); ok {
		// If file is a DatabaseFile that is gzippable and is not fulltext
		// indexed, its contents are already gzipped. We can reach directly
		// into its buffer and skip the gzipping step.
		if databaseFile.fileType.IsGzippable && !databaseFile.isFulltextIndexed {
			if hasMaxAge {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Type", fileType.ContentType)
				w.Header().Set("Cache-Control", cacheControl)
				http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(databaseFile.buf.Bytes()))
				return
			}
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			_, err := hasher.Write(databaseFile.buf.Bytes())
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(databaseFile.buf.Bytes()))
			return
		}
	}

	// If file is small enough and we want the ETag, we can buffer the entire
	// file into memory, calculate its ETag and serve.
	if fileInfo.Size() <= 1<<20 /* 1 MB */ && !hasMaxAge {
		hasher := hashPool.Get().(hash.Hash)
		defer func() {
			hasher.Reset()
			hashPool.Put(hasher)
		}()
		var buf *bytes.Buffer
		// gzip will at least halve the size of what needs to be buffered
		gzippedSize := fileInfo.Size() >> 1
		if gzippedSize > maxPoolableBufferCapacity {
			buf = bytes.NewBuffer(make([]byte, 0, fileInfo.Size()))
		} else {
			buf = bufPool.Get().(*bytes.Buffer)
			defer func() {
				buf.Reset()
				bufPool.Put(buf)
			}()
		}
		multiWriter := io.MultiWriter(buf, hasher)
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(multiWriter)
		defer func() {
			gzipWriter.Reset(io.Discard)
			gzipWriterPool.Put(gzipWriter)
		}()
		_, err := io.Copy(gzipWriter, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		var b [blake2b.Size256]byte
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", fileType.ContentType)
		w.Header().Set("Cache-Control", cacheControl)
		w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(buf.Bytes()))
		return
	}

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", fileType.ContentType)
	w.Header().Set("Cache-Control", cacheControl)
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(w)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, err := io.Copy(gzipWriter, file)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
	} else {
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
	}
}
