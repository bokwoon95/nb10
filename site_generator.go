package nb10

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template/parse"

	"github.com/bokwoon95/nb10/sq"
	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
	"golang.org/x/sync/errgroup"
)

type SiteGenerator struct {
	Site               Site
	fsys               FS
	sitePrefix         string
	contentDomain      string
	imgDomain          string
	markdown           goldmark.Markdown
	mu                 sync.Mutex
	templateCache      map[string]*template.Template
	templateInProgress map[string]chan struct{}
	imgFileIDs         map[string][16]byte
}

type NavigationLink struct {
	Name string
	URL  template.URL
}

type Site struct {
	Lang            string
	Title           string
	Description     template.HTML
	Favicon         template.URL
	NavigationLinks []NavigationLink
}

func NewSiteGenerator(ctx context.Context, fsys FS, sitePrefix, contentDomain, imgDomain string) (*SiteGenerator, error) {
	siteGen := &SiteGenerator{
		fsys:               fsys,
		sitePrefix:         sitePrefix,
		contentDomain:      contentDomain,
		imgDomain:          imgDomain,
		mu:                 sync.Mutex{},
		templateCache:      make(map[string]*template.Template),
		templateInProgress: make(map[string]chan struct{}),
	}
	var config struct {
		Lang            string
		Title           string
		Description     string
		Emoji           string
		Favicon         string
		CodeStyle       string
		NavigationLinks []NavigationLink
	}
	b, err := fs.ReadFile(fsys, path.Join(sitePrefix, "site.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(b) > 0 {
		err := json.Unmarshal(b, &config)
		if err != nil {
			return nil, err
		}
	}
	if config.Lang == "" {
		config.Lang = "en"
	}
	if config.Emoji == "" {
		config.Emoji = "☕"
	}
	if config.Favicon == "" {
		config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + config.Emoji + "</text></svg>"
	}
	if config.CodeStyle == "" {
		config.CodeStyle = "onedark"
	}
	if len(config.NavigationLinks) == 0 {
		home := strings.TrimPrefix(sitePrefix, "@")
		if home == "" {
			home = "home"
		}
		config.NavigationLinks = []NavigationLink{
			{Name: home, URL: "/"},
			{Name: "posts", URL: "/posts/"},
		}
	}
	siteGen.markdown = goldmark.New(
		goldmark.WithParserOptions(parser.WithAttribute()),
		goldmark.WithExtensions(
			extension.Table,
			highlighting.NewHighlighting(highlighting.WithStyle(config.CodeStyle)),
		),
		goldmark.WithRendererOptions(
			goldmarkhtml.WithHardWraps(),
			goldmarkhtml.WithUnsafe(),
		),
	)
	siteGen.Site = Site{
		Lang:            config.Lang,
		Title:           config.Title,
		Favicon:         template.URL(config.Favicon),
		NavigationLinks: config.NavigationLinks,
	}
	if config.Description != "" {
		var b strings.Builder
		err := siteGen.markdown.Convert([]byte(config.Description), &b)
		if err != nil {
			return nil, err
		}
		siteGen.Site.Description = template.HTML(b.String())
	}
	if siteGen.imgDomain == "" {
		return siteGen, nil
	}
	remoteFS, ok := siteGen.fsys.(*RemoteFS)
	if !ok {
		return siteGen, nil
	}
	_, isS3Storage := remoteFS.Storage.(*S3Storage)
	if !isS3Storage {
		return siteGen, nil
	}
	cursor, err := sq.FetchCursor(ctx, remoteFS.DB, sq.Query{
		Dialect: remoteFS.Dialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE file_path LIKE {pattern}" +
			" AND (" +
			"file_path LIKE '%.jpeg'" +
			" OR file_path LIKE '%.jpg'" +
			" OR file_path LIKE '%.png'" +
			" OR file_path LIKE '%.webp'" +
			" OR file_path LIKE '%.gif'" +
			") ",
		Values: []any{
			sq.StringParam("pattern", path.Join(siteGen.sitePrefix, "output")+"/%"),
		},
	}, func(row *sq.Row) (result struct {
		FileID   [16]byte
		FilePath string
	}) {
		result.FileID = row.UUID("file_id")
		result.FilePath = row.String("file_path")
		return result
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	siteGen.imgFileIDs = make(map[string][16]byte)
	for cursor.Next() {
		result, err := cursor.Result()
		if err != nil {
			return nil, err
		}
		siteGen.imgFileIDs[result.FilePath] = result.FileID
	}
	err = cursor.Close()
	if err != nil {
		return nil, err
	}
	return siteGen, nil
}

func (siteGen *SiteGenerator) ParseTemplate(groupctx context.Context, name, text string, callers []string) (*template.Template, error) {
	currentTemplate, err := template.New(name).Funcs(funcMap).Parse(text)
	if err != nil {
		return nil, NewTemplateError(err)
	}
	internalTemplates := currentTemplate.Templates()
	slices.SortFunc(internalTemplates, func(a, b *template.Template) int {
		return strings.Compare(a.Name(), b.Name())
	})
	for _, tmpl := range internalTemplates {
		internalName := tmpl.Name()
		if strings.HasSuffix(internalName, ".html") && internalName != name {
			return nil, TemplateError{
				Name:         name,
				ErrorMessage: "define " + strconv.Quote(internalName) + ": internal template name cannot end with .html",
			}
		}
	}

	// Get the list of external templates referenced by the current template.
	var externalNames []string
	var node parse.Node
	var nodes []parse.Node
	for _, tmpl := range internalTemplates {
		if tmpl.Tree == nil || tmpl.Tree.Root == nil {
			continue
		}
		nodes = append(nodes, tmpl.Tree.Root.Nodes...)
		for len(nodes) > 0 {
			node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
			switch node := node.(type) {
			case *parse.ListNode:
				if node == nil {
					continue
				}
				nodes = append(nodes, node.Nodes...)
			case *parse.BranchNode:
				nodes = append(nodes, node.List, node.ElseList)
			case *parse.RangeNode:
				nodes = append(nodes, node.List, node.ElseList)
			case *parse.TemplateNode:
				if strings.HasSuffix(node.Name, ".html") {
					if !strings.HasPrefix(node.Name, "/themes/") {
						return nil, TemplateError{
							Name:         name,
							ErrorMessage: "template " + strconv.Quote(node.Name) + ": external template name must start with /themes/",
						}
					}
					externalNames = append(externalNames, node.Name)
				}
			}
		}
	}
	// sort | uniq deduplication.
	slices.Sort(externalNames)
	externalNames = slices.Compact(externalNames)

	group, groupctx := errgroup.WithContext(groupctx)
	externalTemplates := make([]*template.Template, len(externalNames))
	for i, externalName := range externalNames {
		i, externalName := i, externalName
		group.Go(func() error {
			n := slices.Index(callers, externalName)
			if n > 0 {
				return TemplateError{
					Name:         externalName,
					ErrorMessage: "circular template reference: " + strings.Join(callers[n:], "=>") + " => " + externalName,
				}
			}

			// If a template is currently being parsed, wait for it to finish
			// before checking the templateCache for the result.
			siteGen.mu.Lock()
			wait := siteGen.templateInProgress[externalName]
			siteGen.mu.Unlock()
			if wait != nil {
				select {
				case <-groupctx.Done():
					return groupctx.Err()
				case <-wait:
					break
				}
			}
			siteGen.mu.Lock()
			cachedTemplate, ok := siteGen.templateCache[externalName]
			siteGen.mu.Unlock()
			if ok {
				// We found the template; add it to the slice and exit. Note
				// that the cachedTemplate may be nil, if parsing that template
				// had resulted in errors.
				externalTemplates[i] = cachedTemplate
				return nil
			}

			// We put a nil pointer into the templateCache first. This is to
			// indicate that we have already seen this template. If parsing
			// succeeds, we simply overwrite the nil entry with the parsed
			// template. If we fail, the cachedTemplate pointer stays nil and
			// should be treated as a signal by other goroutines that parsing
			// this template has errors. Other goroutines are blocked from
			// accessing the cachedTemplate pointer until the wait channel is
			// closed by the defer function below (once this goroutine exits).
			wait = make(chan struct{})
			siteGen.mu.Lock()
			siteGen.templateCache[externalName] = nil
			siteGen.templateInProgress[externalName] = wait
			siteGen.mu.Unlock()
			defer func() {
				siteGen.mu.Lock()
				siteGen.templateCache[externalName] = cachedTemplate
				delete(siteGen.templateInProgress, externalName)
				close(wait)
				siteGen.mu.Unlock()
			}()

			file, err := siteGen.fsys.WithContext(groupctx).Open(path.Join(siteGen.sitePrefix, "output", externalName))
			if err != nil {
				// If we cannot find the referenced template, it is not the
				// external template's fault but rather the current template's
				// fault for referencing a non-existent external template.
				// Therefore we return the error (associating it with the
				// current template) instead of adding it to the
				// externalTemplateErrs list.
				if errors.Is(err, fs.ErrNotExist) {
					return TemplateError{
						Name:         name,
						ErrorMessage: "template " + strconv.Quote(externalName) + " does not exist",
					}
				}
				return err
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return err
			}
			if fileInfo.IsDir() {
				// If the referenced template is not a file but a directory, it
				// is the current template's fault for referencing a directory
				// instead of a file. Therefore we return the error
				// (associating it with the current template) instead of adding
				// it to the externalTemplateErrs list.
				return TemplateError{
					Name:         name,
					ErrorMessage: strconv.Quote(externalName) + " is a folder",
				}
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return err
			}
			err = file.Close()
			if err != nil {
				return err
			}
			newCallers := append(append(make([]string, 0, len(callers)+1), callers...), externalName)
			externalTemplate, err := siteGen.ParseTemplate(groupctx, externalName, b.String(), newCallers)
			if err != nil {
				return err
			}
			// Important! Before we execute any template, it must be cloned.
			// This is because once a template has been executed it is no
			// longer pristine i.e. it cannot be added to another template
			// using AddParseTree (html/template has this restriction in order
			// for its contextually auto-escaped HTML feature to work).
			externalTemplates[i], err = externalTemplate.Clone()
			if err != nil {
				return err
			}
			cachedTemplate = externalTemplate
			return nil
		})
	}
	err = group.Wait()
	if err != nil {
		return nil, err
	}

	finalTemplate := template.New(name).Funcs(funcMap)
	for i, tmpl := range externalTemplates {
		for _, tmpl := range tmpl.Templates() {
			_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
			if err != nil {
				return nil, TemplateError{
					Name:         name,
					ErrorMessage: fmt.Sprintf("%s: add %s: %s", externalNames[i], tmpl.Name(), err),
				}
			}
		}
	}
	for _, tmpl := range internalTemplates {
		_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
		if err != nil {
			return nil, TemplateError{
				Name:         name,
				ErrorMessage: fmt.Sprintf("add %s: %s", tmpl.Name(), err),
			}
		}
	}
	return finalTemplate.Lookup(name), nil
}

var (
	postRegexp     = regexp.MustCompile(`^/posts(?:/.*)?/post.html(?P<line>:\d+)(?P<col>:\d+)?:\s+(?P<msg>.*)$`)
	postlistRegexp = regexp.MustCompile(`^/posts(?:/.*)?/postlist.html(?P<line>:\d+)(?P<col>:\d+)?:\s+(?P<msg>.*)$`)
)

// /posts/pages/
// {{ template "/themes/github.com/bokwoon95/" }}
// ParseTemplate("posts/post.html", content)
// pages/abcd.html    <= relative filePath means it doesn't belong in the output directory.
// posts/post.html    <= relative filePath means
// /themes/index.html <= absolute filePath means it belongs inside the output directory.
// <img src='/themes/one-two-three.jpeg'>

type TemplateError struct {
	Name         string
	Line         int
	ErrorMessage string
}

func NewTemplateError(err error) error {
	sections := strings.SplitN(err.Error(), ":", 4)
	if len(sections) < 4 || strings.TrimSpace(sections[0]) != "template" {
		return TemplateError{
			ErrorMessage: err.Error(),
		}
	}
	templateName := strings.TrimSpace(sections[1])
	lineNo, _ := strconv.Atoi(strings.TrimSpace(sections[2]))
	errorMessage := strings.TrimSpace(sections[3])
	i := strings.Index(errorMessage, ":")
	if i > 0 {
		colNo, _ := strconv.Atoi(strings.TrimSpace(errorMessage[:i]))
		if colNo > 0 {
			errorMessage = strings.TrimSpace(errorMessage[i+1:])
		}
	}
	var oldnew []string
	if matches := postRegexp.FindAllString(errorMessage, -1); len(matches) > 0 {
		slices.Sort(matches)
		matches = slices.Compact(matches)
		for _, match := range matches {
			lineNo, _ := strconv.Atoi(strings.TrimPrefix(match, "/themes/post.html:"))
			oldnew = append(oldnew, match, "/themes/post.html:"+strconv.Itoa(lineNo-5))
		}
	}
	if matches := postlistRegexp.FindAllString(errorMessage, -1); len(matches) > 0 {
		slices.Sort(matches)
		matches = slices.Compact(matches)
		for _, match := range matches {
			lineNo, _ := strconv.Atoi(strings.TrimPrefix(match, "/themes/postlist.html:"))
			oldnew = append(oldnew, match, "/themes/postlist.html:"+strconv.Itoa(lineNo-6))
		}
	}
	offset := 0
	if templateName == "post.html" {
		offset = 5
	} else if templateName == "postlist.html" {
		offset = 6
	} else if strings.HasPrefix(templateName, "/pages/") {
		offset = 5
		pageRegexp, err := regexp.Compile(templateName + `:\d+`)
		if err == nil {
			if matches := pageRegexp.FindAllString(errorMessage, -1); len(matches) > 0 {
				slices.Sort(matches)
				matches = slices.Compact(matches)
				for _, match := range matches {
					lineNo, _ := strconv.Atoi(strings.TrimPrefix(match, templateName+":"))
					oldnew = append(oldnew, match, "/themes/post.html:"+strconv.Itoa(lineNo-5))
				}
			}
		}
	}
	if len(oldnew) > 0 {
		errorMessage = strings.NewReplacer(oldnew...).Replace(errorMessage)
	}
	return TemplateError{
		Name:         templateName,
		Line:         lineNo - offset,
		ErrorMessage: errorMessage,
	}
}

func (templateErr TemplateError) Error() string {
	if templateErr.Name == "" {
		return templateErr.ErrorMessage
	}
	if templateErr.Line == 0 {
		return templateErr.Name + ": " + templateErr.ErrorMessage
	}
	return templateErr.Name + ":" + strconv.Itoa(templateErr.Line) + ": " + templateErr.ErrorMessage
}

var funcMap = map[string]any{
	"join":             path.Join,
	"base":             path.Base,
	"ext":              path.Ext,
	"hasPrefix":        strings.HasPrefix,
	"hasSuffix":        strings.HasSuffix,
	"trimPrefix":       strings.TrimPrefix,
	"trimSuffix":       strings.TrimSuffix,
	"fileSizeToString": fileSizeToString,
	"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
	"head": func(s string) string {
		head, _, _ := strings.Cut(s, "/")
		return head
	},
	"tail": func(s string) string {
		_, tail, _ := strings.Cut(s, "/")
		return tail
	},
	"list": func(v ...any) []any { return v },
	"dict": func(v ...any) (map[string]any, error) {
		dict := make(map[string]any)
		if len(dict)%2 != 0 {
			return nil, fmt.Errorf("odd number of arguments passed in")
		}
		for i := 0; i+1 < len(dict); i += 2 {
			key, ok := v[i].(string)
			if !ok {
				return nil, fmt.Errorf("value %d (%#v) is not a string", i, v[i])
			}
			value := v[i+1]
			dict[key] = value
		}
		return dict, nil
	},
	"dump": func(v any) template.HTML {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return template.HTML("<pre style='white-space:pre-wrap;'>" + err.Error() + "</pre>")
		}
		return template.HTML("<pre style='white-space:pre-wrap;'>" + string(b) + "</pre>")
	},
	"throw": func(msg string) (string, error) {
		return "", fmt.Errorf(msg)
	},
}
