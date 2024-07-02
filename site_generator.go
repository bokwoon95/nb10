package nb10

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math"
	"net/url"
	"path"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template/parse"
	"time"

	"github.com/bokwoon95/nb10/sq"
	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
	"golang.org/x/net/html"
	"golang.org/x/sync/errgroup"
)

type SiteGenerator struct {
	Site               Site
	fsys               FS
	sitePrefix         string
	contentDomain      string
	contentDomainHTTPS bool
	imgDomain          string
	port               int
	markdown           goldmark.Markdown
	mu                 sync.Mutex
	templateCache      map[string]*template.Template
	templateInProgress map[string]chan struct{}
	imgFileIDs         map[string]ID
}

type NavigationLink struct {
	Name string
	URL  template.URL
}

type Site struct {
	Lang            string
	Title           string
	Favicon         template.URL
	Description     template.HTML
	NavigationLinks []NavigationLink
}

type SiteGeneratorConfig struct {
	FS                 FS
	ContentDomain      string
	ContentDomainHTTPS bool
	ImgDomain          string
	SitePrefix         string
}

func NewSiteGenerator(ctx context.Context, siteGenConfig SiteGeneratorConfig) (*SiteGenerator, error) {
	siteGen := &SiteGenerator{
		fsys:               siteGenConfig.FS,
		sitePrefix:         siteGenConfig.SitePrefix,
		contentDomain:      siteGenConfig.ContentDomain,
		contentDomainHTTPS: siteGenConfig.ContentDomainHTTPS,
		imgDomain:          siteGenConfig.ImgDomain,
		mu:                 sync.Mutex{},
		templateCache:      make(map[string]*template.Template),
		templateInProgress: make(map[string]chan struct{}),
	}
	var config struct {
		Lang            string
		Title           string
		Emoji           string
		Favicon         string
		CodeStyle       string
		Description     string
		NavigationLinks []NavigationLink
	}
	b, err := fs.ReadFile(siteGen.fsys, path.Join(siteGen.sitePrefix, "site.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(b) > 0 {
		err := json.Unmarshal(b, &config)
		if err != nil {
			return nil, err
		}
	} else {
		config.Lang = "en"
		config.Emoji = "☕"
		config.CodeStyle = "onedark"
		var home string
		siteName := strings.TrimPrefix(siteGen.sitePrefix, "@")
		if siteName == "" {
			home = "home"
		} else if strings.Contains(siteName, ".") {
			home = siteName
		} else {
			home = siteName + "." + siteGen.contentDomain
		}
		config.NavigationLinks = []NavigationLink{
			{Name: home, URL: "/"},
			{Name: "posts", URL: "/posts/"},
		}
	}
	if config.Favicon == "" {
		emoji := config.Emoji
		if emoji == "" {
			emoji = "☕"
		}
		config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + emoji + "</text></svg>"
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
	databaseFS, ok := siteGen.fsys.(*DatabaseFS)
	if !ok {
		return siteGen, nil
	}
	cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
		Dialect: databaseFS.Dialect,
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
		FileID   ID
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
	siteGen.imgFileIDs = make(map[string]ID)
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

func (siteGen *SiteGenerator) ParseTemplate(ctx context.Context, name, text string) (*template.Template, error) {
	return siteGen.parseTemplate(ctx, name, text, nil)
}

func (siteGen *SiteGenerator) parseTemplate(ctx context.Context, name, text string, callers []string) (*template.Template, error) {
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
	_ = template.ParseFiles

	group, groupctx := errgroup.WithContext(ctx)
	externalTemplates := make([]*template.Template, len(externalNames))
	for i, externalName := range externalNames {
		i, externalName := i, externalName
		group.Go(func() (err error) {
			defer func() {
				if v := recover(); v != nil {
					err = fmt.Errorf("panic: " + string(debug.Stack()))
				}
			}()
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
			externalTemplate, err := siteGen.parseTemplate(groupctx, externalName, b.String(), newCallers)
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
	for i, externalTemplate := range externalTemplates {
		for _, tmpl := range externalTemplate.Templates() {
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

type PageData struct {
	Site             Site
	Parent           string
	Name             string
	ChildPages       []Page
	Markdown         map[string]template.HTML
	Images           []Image
	ModificationTime time.Time
}

type Page struct {
	Parent string
	Name   string
	Title  string
}

type Image struct {
	Parent  string
	Name    string
	AltText string
	Caption template.HTML
}

func (siteGen *SiteGenerator) GeneratePage(ctx context.Context, filePath, text string) error {
	urlPath := strings.TrimPrefix(filePath, "pages/")
	if urlPath == "index.html" {
		urlPath = ""
	} else {
		urlPath = strings.TrimSuffix(urlPath, path.Ext(urlPath))
	}
	outputDir := path.Join(siteGen.sitePrefix, "output", urlPath)
	pageData := PageData{
		Site:             siteGen.Site,
		Parent:           path.Dir(urlPath),
		Name:             path.Base(urlPath),
		ChildPages:       []Page{},
		Markdown:         make(map[string]template.HTML),
		Images:           []Image{},
		ModificationTime: time.Now().UTC(),
	}
	if pageData.Parent == "." {
		pageData.Parent = ""
	}
	var err error
	var tmpl *template.Template
	group, groupctx := errgroup.WithContext(ctx)
	group.Go(func() (err error) {
		defer func() {
			if v := recover(); v != nil {
				err = fmt.Errorf("panic: " + string(debug.Stack()))
			}
		}()
		tmpl, err = siteGen.ParseTemplate(groupctx, "/"+filePath, text)
		if err != nil {
			return err
		}
		return nil
	})
	group.Go(func() (err error) {
		defer func() {
			if v := recover(); v != nil {
				err = fmt.Errorf("panic: " + string(debug.Stack()))
			}
		}()
		markdownMu := sync.Mutex{}
		if databaseFS, ok := siteGen.fsys.(*DatabaseFS); ok {
			cursor, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
					" AND NOT is_dir" +
					" AND (" +
					"file_path LIKE '%.jpeg'" +
					" OR file_path LIKE '%.jpg'" +
					" OR file_path LIKE '%.png'" +
					" OR file_path LIKE '%.webp'" +
					" OR file_path LIKE '%.gif'" +
					" OR file_path LIKE '%.md'" +
					") " +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("outputDir", outputDir),
				},
			}, func(row *sq.Row) (result struct {
				FilePath string
				Text     []byte
			}) {
				result.FilePath = row.String("file_path")
				result.Text = row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "text")
				return result
			})
			if err != nil {
				return err
			}
			defer cursor.Close()
			subgroup, subctx := errgroup.WithContext(groupctx)
			for cursor.Next() {
				result, err := cursor.Result()
				if err != nil {
					return err
				}
				name := path.Base(result.FilePath)
				switch path.Ext(result.FilePath) {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					pageData.Images = append(pageData.Images, Image{
						Parent: urlPath,
						Name:   name,
					})
					i := len(pageData.Images) - 1
					subgroup.Go(func() (err error) {
						defer func() {
							if v := recover(); v != nil {
								err = fmt.Errorf("panic: " + string(debug.Stack()))
							}
							result.Text = result.Text[:0]
							bufPool.Put(bytes.NewBuffer(result.Text))
						}()
						err = subctx.Err()
						if err != nil {
							return err
						}
						var altText []byte
						result.Text = bytes.TrimSpace(result.Text)
						if bytes.HasPrefix(result.Text, []byte("!alt ")) {
							altText, result.Text, _ = bytes.Cut(result.Text, []byte("\n"))
							altText = bytes.TrimSpace(bytes.TrimPrefix(altText, []byte("!alt ")))
							result.Text = bytes.TrimSpace(result.Text)
						}
						var b strings.Builder
						err = siteGen.markdown.Convert(result.Text, &b)
						if err != nil {
							return err
						}
						pageData.Images[i].AltText = string(altText)
						pageData.Images[i].Caption = template.HTML(b.String())
						return nil
					})
				case ".md":
					subgroup.Go(func() (err error) {
						defer func() {
							if v := recover(); v != nil {
								err = fmt.Errorf("panic: " + string(debug.Stack()))
							}
							result.Text = result.Text[:0]
							bufPool.Put(bytes.NewBuffer(result.Text))
						}()
						err = subctx.Err()
						if err != nil {
							return err
						}
						var b strings.Builder
						err = siteGen.markdown.Convert(result.Text, &b)
						if err != nil {
							return err
						}
						markdownMu.Lock()
						pageData.Markdown[name] = template.HTML(b.String())
						markdownMu.Unlock()
						return nil
					})
				}
			}
			err = cursor.Close()
			if err != nil {
				return err
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
		} else {
			dirEntries, err := siteGen.fsys.WithContext(groupctx).ReadDir(outputDir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			subgroup, subctx := errgroup.WithContext(groupctx)
			for _, dirEntry := range dirEntries {
				dirEntry := dirEntry
				name := dirEntry.Name()
				switch path.Ext(name) {
				case ".jpeg", ".jpg", ".png", ".webp", ".gif":
					pageData.Images = append(pageData.Images, Image{Parent: urlPath, Name: name})
				case ".md":
					subgroup.Go(func() (err error) {
						defer func() {
							if v := recover(); v != nil {
								err = fmt.Errorf("panic: " + string(debug.Stack()))
							}
						}()
						file, err := siteGen.fsys.WithContext(subctx).Open(path.Join(outputDir, name))
						if err != nil {
							return err
						}
						defer file.Close()
						buf := bufPool.Get().(*bytes.Buffer)
						defer func() {
							if buf.Cap() <= maxPoolableBufferCapacity {
								buf.Reset()
								bufPool.Put(buf)
							}
						}()
						_, err = buf.ReadFrom(file)
						if err != nil {
							return err
						}
						var b strings.Builder
						err = siteGen.markdown.Convert(buf.Bytes(), &b)
						if err != nil {
							return err
						}
						markdownMu.Lock()
						pageData.Markdown[name] = template.HTML(b.String())
						markdownMu.Unlock()
						return nil
					})
				}
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
		}
		return nil
	})
	group.Go(func() (err error) {
		defer func() {
			if v := recover(); v != nil {
				err = fmt.Errorf("panic: " + string(debug.Stack()))
			}
		}()
		pageDir := path.Join(siteGen.sitePrefix, "pages", urlPath)
		if databaseFS, ok := siteGen.fsys.(*DatabaseFS); ok {
			pageData.ChildPages, err = sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {pageDir})" +
					" AND NOT is_dir" +
					" AND file_path LIKE '%.html'" +
					" ORDER BY file_path",
				Values: []any{
					sq.StringParam("pageDir", pageDir),
				},
			}, func(row *sq.Row) Page {
				page := Page{
					Parent: urlPath,
					Name:   path.Base(row.String("file_path")),
				}
				// NOTE: oh my god we do title detection here but what if the
				// user wants to use 1. set a custom lang or 2. use a custom
				// favicon? Then <!DOCTYPE> has to come first :/ and we can't
				// use <!-- #title --> anymore
				line := strings.TrimSpace(row.String("{}", sq.DialectExpression{
					Default: sq.Expr("substr(text, 1, instr(text, char(10))-1)"),
					Cases: []sq.DialectCase{{
						Dialect: "postgres",
						Result:  sq.Expr("split_part(text, chr(10), 1)"),
					}, {
						Dialect: "mysql",
						Result:  sq.Expr("substring_index(text, char(10), 1)"),
					}},
				}))
				if !strings.HasPrefix(line, "<!--") {
					return page
				}
				line = strings.TrimSpace(strings.TrimPrefix(line, "<!--"))
				if !strings.HasPrefix(line, "#title") {
					return page
				}
				line = strings.TrimSpace(strings.TrimPrefix(line, "#title"))
				if !strings.HasSuffix(line, "-->") {
					return page
				}
				page.Title = strings.TrimSpace(strings.TrimSuffix(line, "-->"))
				return page
			})
			if err != nil {
				return err
			}
		} else {
			dirEntries, err := siteGen.fsys.WithContext(groupctx).ReadDir(pageDir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			pageData.ChildPages = make([]Page, len(dirEntries))
			subgroup, subctx := errgroup.WithContext(groupctx)
			for i, dirEntry := range dirEntries {
				i, dirEntry := i, dirEntry
				subgroup.Go(func() (err error) {
					defer func() {
						if v := recover(); v != nil {
							err = fmt.Errorf("panic: " + string(debug.Stack()))
						}
					}()
					name := dirEntry.Name()
					if dirEntry.IsDir() || !strings.HasSuffix(name, ".html") {
						return nil
					}
					pageData.ChildPages[i].Parent = urlPath
					pageData.ChildPages[i].Name = name
					file, err := siteGen.fsys.WithContext(subctx).Open(path.Join(pageDir, name))
					if err != nil {
						return err
					}
					defer file.Close()
					reader := readerPool.Get().(*bufio.Reader)
					reader.Reset(file)
					defer func() {
						reader.Reset(empty)
						readerPool.Put(reader)
					}()
					done := false
					for !done {
						line, err := reader.ReadSlice('\n')
						if err != nil {
							if err != io.EOF {
								return err
							}
							done = true
						}
						line = bytes.TrimSpace(line)
						if !bytes.HasPrefix(line, []byte("<!--")) {
							break
						}
						line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("<!--")))
						if !bytes.HasPrefix(line, []byte("#title")) {
							break
						}
						line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("#title")))
						if !bytes.HasSuffix(line, []byte("-->")) {
							break
						}
						pageData.ChildPages[i].Title = string(bytes.TrimSpace(bytes.TrimSuffix(line, []byte("-->"))))
						break
					}
					return nil
				})
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
			n := 0
			for _, childPage := range pageData.ChildPages {
				if childPage != (Page{}) {
					pageData.ChildPages[n] = childPage
					n++
				}
			}
			pageData.ChildPages = pageData.ChildPages[:n]
		}
		return nil
	})
	err = group.Wait()
	if err != nil {
		return err
	}
	writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		err := siteGen.fsys.WithContext(ctx).MkdirAll(outputDir, 0755)
		if err != nil {
			return err
		}
		writer, err = siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			return err
		}
	}
	defer writer.Close()
	_, err = io.WriteString(writer, "<!DOCTYPE html>\n"+
		"<html lang='"+template.HTMLEscapeString(siteGen.Site.Lang)+"'>\n"+
		"<meta charset='utf-8'>\n"+
		"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"+
		"<link rel='icon' href='"+template.HTMLEscapeString(string(siteGen.Site.Favicon))+"'>\n",
	)
	if err != nil {
		return err
	}
	_, isDatabaseFS := siteGen.fsys.(*DatabaseFS)
	if siteGen.imgDomain != "" && isDatabaseFS {
		pipeReader, pipeWriter := io.Pipe()
		result := make(chan error, 1)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					result <- fmt.Errorf("panic: " + string(debug.Stack()))
				}
			}()
			result <- siteGen.rewriteURLs(writer, pipeReader, urlPath)
		}()
		err = tmpl.Execute(pipeWriter, &pageData)
		if err != nil {
			return NewTemplateError(err)
		}
		pipeWriter.Close()
		err = <-result
		if err != nil {
			return err
		}
	} else {
		err = tmpl.Execute(writer, &pageData)
		if err != nil {
			return NewTemplateError(err)
		}
	}
	err = writer.Close()
	if err != nil {
		return err
	}
	return nil
}

type PostData struct {
	Site             Site
	Category         string
	Name             string
	Title            string
	Content          template.HTML
	Images           []Image
	CreationTime     time.Time
	ModificationTime time.Time
}

func (siteGen *SiteGenerator) GeneratePost(ctx context.Context, filePath, text string, creationTime time.Time, tmpl *template.Template) error {
	timestampPrefix, _, _ := strings.Cut(path.Base(filePath), "-")
	if len(timestampPrefix) > 0 && len(timestampPrefix) <= 8 {
		b, err := base32Encoding.DecodeString(fmt.Sprintf("%08s", timestampPrefix))
		if len(b) == 5 && err == nil {
			var timestamp [8]byte
			copy(timestamp[len(timestamp)-5:], b)
			creationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
		}
	}
	urlPath := strings.TrimSuffix(filePath, path.Ext(filePath))
	outputDir := path.Join(siteGen.sitePrefix, "output", urlPath)
	postData := PostData{
		Site:             siteGen.Site,
		Category:         path.Dir(strings.TrimPrefix(urlPath, "posts/")),
		Name:             path.Base(strings.TrimPrefix(urlPath, "posts/")),
		Images:           []Image{},
		CreationTime:     creationTime,
		ModificationTime: time.Now().UTC(),
	}
	if strings.Contains(postData.Category, "/") {
		return fmt.Errorf("invalid post category")
	}
	if postData.Category == "." {
		postData.Category = ""
	}
	// Title
	var line string
	remainder := text
	for len(remainder) > 0 {
		line, remainder, _ = strings.Cut(remainder, "\n")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		postData.Title = stripMarkdownStyles(siteGen.markdown, []byte(line))
		break
	}
	if postData.Title == "" {
		postData.Title = postData.Name
	}
	// Content
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		bufPool.Put(buf)
	}()
	err := siteGen.markdown.Convert([]byte(text), buf)
	if err != nil {
		return err
	}
	postData.Content = template.HTML(buf.String())
	imgIsMentioned := make(map[string]struct{})
	tokenizer := html.NewTokenizer(bytes.NewReader(buf.Bytes()))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			err := tokenizer.Err()
			if err == io.EOF {
				break
			}
			return err
		}
		if tokenType == html.SelfClosingTagToken || tokenType == html.StartTagToken {
			var key, val []byte
			name, moreAttr := tokenizer.TagName()
			if !bytes.Equal(name, []byte("img")) {
				continue
			}
			for moreAttr {
				key, val, moreAttr = tokenizer.TagAttr()
				if !bytes.Equal(key, []byte("src")) {
					continue
				}
				uri, err := url.Parse(string(val))
				if err != nil {
					continue
				}
				if uri.Scheme != "" || uri.Host != "" || strings.Contains(uri.Path, "/") {
					continue
				}
				imgIsMentioned[uri.Path] = struct{}{}
			}
		}
	}
	if databaseFS, ok := siteGen.fsys.(*DatabaseFS); ok {
		cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {outputDir})" +
				" AND NOT is_dir" +
				" AND (" +
				"file_path LIKE '%.jpeg'" +
				" OR file_path LIKE '%.jpg'" +
				" OR file_path LIKE '%.png'" +
				" OR file_path LIKE '%.webp'" +
				" OR file_path LIKE '%.gif'" +
				") " +
				" ORDER BY file_path",
			Values: []any{
				sq.StringParam("outputDir", outputDir),
			},
		}, func(row *sq.Row) (result struct {
			FilePath string
			Text     []byte
		}) {
			result.FilePath = row.String("file_path")
			result.Text = row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "text")
			return result
		})
		if err != nil {
			return err
		}
		defer cursor.Close()
		group, groupctx := errgroup.WithContext(ctx)
		for cursor.Next() {
			result, err := cursor.Result()
			if err != nil {
				return err
			}
			name := path.Base(result.FilePath)
			if _, ok := imgIsMentioned[name]; ok {
				continue
			}
			postData.Images = append(postData.Images, Image{
				Parent: urlPath,
				Name:   name,
			})
			i := len(postData.Images) - 1
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
					result.Text = result.Text[:0]
					bufPool.Put(bytes.NewBuffer(result.Text))
				}()
				err = groupctx.Err()
				if err != nil {
					return err
				}
				var altText []byte
				result.Text = bytes.TrimSpace(result.Text)
				if bytes.HasPrefix(result.Text, []byte("!alt ")) {
					altText, result.Text, _ = bytes.Cut(result.Text, []byte("\n"))
					altText = bytes.TrimSpace(bytes.TrimPrefix(altText, []byte("!alt ")))
					result.Text = bytes.TrimSpace(result.Text)
				}
				var b strings.Builder
				err = siteGen.markdown.Convert(result.Text, &b)
				if err != nil {
					return err
				}
				postData.Images[i].AltText = string(altText)
				postData.Images[i].Caption = template.HTML(b.String())
				return nil
			})
		}
		err = cursor.Close()
		if err != nil {
			return err
		}
		err = group.Wait()
		if err != nil {
			return err
		}
	} else {
		dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(outputDir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		for _, dirEntry := range dirEntries {
			name := dirEntry.Name()
			if dirEntry.IsDir() {
				continue
			}
			switch path.Ext(name) {
			case ".jpeg", ".jpg", ".png", ".webp", ".gif":
				if _, ok := imgIsMentioned[name]; ok {
					continue
				}
				postData.Images = append(postData.Images, Image{Parent: urlPath, Name: name})
			}
		}
	}
	writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		err := siteGen.fsys.WithContext(ctx).MkdirAll(outputDir, 0755)
		if err != nil {
			return err
		}
		writer, err = siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			return err
		}
	}
	defer writer.Close()
	_, err = io.WriteString(writer, "<!DOCTYPE html>\n"+
		"<html lang='"+template.HTMLEscapeString(siteGen.Site.Lang)+"'>\n"+
		"<meta charset='utf-8'>\n"+
		"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"+
		"<link rel='icon' href='"+template.HTMLEscapeString(string(siteGen.Site.Favicon))+"'>\n",
	)
	if err != nil {
		return err
	}
	_, isDatabaseFS := siteGen.fsys.(*DatabaseFS)
	if siteGen.imgDomain != "" && isDatabaseFS {
		pipeReader, pipeWriter := io.Pipe()
		result := make(chan error, 1)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					result <- fmt.Errorf("panic: " + string(debug.Stack()))
				}
			}()
			result <- siteGen.rewriteURLs(writer, pipeReader, urlPath)
		}()
		err = tmpl.Execute(pipeWriter, &postData)
		if err != nil {
			return NewTemplateError(err)
		}
		pipeWriter.Close()
		err = <-result
		if err != nil {
			return err
		}
	} else {
		err = tmpl.Execute(writer, &postData)
		if err != nil {
			return NewTemplateError(err)
		}
	}
	err = writer.Close()
	if err != nil {
		return err
	}
	return nil
}

func (siteGen *SiteGenerator) GeneratePosts(ctx context.Context, category string, tmpl *template.Template) (int64, error) {
	if databaseFS, ok := siteGen.fsys.(*DatabaseFS); ok {
		type File struct {
			FilePath     string
			Text         string
			CreationTime time.Time
		}
		cursor, err := sq.FetchCursor(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
				" AND NOT is_dir" +
				" AND file_path LIKE '%.md'",
			Values: []any{
				sq.StringParam("parent", path.Join(siteGen.sitePrefix, "posts", category)),
			},
		}, func(row *sq.Row) File {
			return File{
				FilePath:     row.String("file_path"),
				Text:         row.String("text"),
				CreationTime: row.Time("creation_time"),
			}
		})
		if err != nil {
			return 0, err
		}
		defer cursor.Close()
		var count atomic.Int64
		group, groupctx := errgroup.WithContext(ctx)
		for cursor.Next() {
			file, err := cursor.Result()
			if err != nil {
				return 0, err
			}
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				if siteGen.sitePrefix != "" {
					_, file.FilePath, _ = strings.Cut(file.FilePath, "/")
				}
				err = siteGen.GeneratePost(groupctx, file.FilePath, file.Text, file.CreationTime, tmpl)
				if err != nil {
					return err
				}
				count.Add(1)
				return nil
			})
		}
		err = cursor.Close()
		if err != nil {
			return 0, err
		}
		err = group.Wait()
		if err != nil {
			return count.Load(), err
		}
		return count.Load(), nil
	}
	dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(path.Join(siteGen.sitePrefix, "posts", category))
	if err != nil {
		return 0, err
	}
	var count atomic.Int64
	group, groupctx := errgroup.WithContext(ctx)
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}
		name := dirEntry.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		group.Go(func() (err error) {
			defer func() {
				if v := recover(); v != nil {
					err = fmt.Errorf("panic: " + string(debug.Stack()))
				}
			}()
			file, err := siteGen.fsys.WithContext(groupctx).Open(path.Join(siteGen.sitePrefix, "posts", category, name))
			if err != nil {
				return err
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return err
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return err
			}
			var absolutePath string
			if dirFS, ok := siteGen.fsys.(*DirFS); ok {
				absolutePath = path.Join(dirFS.RootDir, siteGen.sitePrefix, "posts", category, name)
			}
			creationTime := CreationTime(absolutePath, fileInfo)
			err = siteGen.GeneratePost(groupctx, path.Join("posts", category, name), b.String(), creationTime, tmpl)
			if err != nil {
				return err
			}
			count.Add(1)
			return nil
		})
	}
	err = group.Wait()
	if err != nil {
		return count.Load(), err
	}
	return count.Load(), nil
}

type Post struct {
	Category         string
	Name             string
	Title            string
	Preview          string
	HasMore          bool
	Content          template.HTML
	CreationTime     time.Time
	ModificationTime time.Time
	// A nil []byte slice indicates a lack of a value, a non-nil but empty byte
	// slice indicates an empty value.
	text []byte
}

type PostListData struct {
	Site       Site
	Category   string
	Pagination Pagination
	Posts      []Post
}

func (siteGen *SiteGenerator) GeneratePostList(ctx context.Context, category string, tmpl *template.Template) (int64, error) {
	var config struct {
		PostsPerPage int
	}
	if strings.Contains(category, "/") {
		return 0, fmt.Errorf("invalid post category")
	}
	b, err := fs.ReadFile(siteGen.fsys.WithContext(ctx), path.Join(siteGen.sitePrefix, "posts", category, "postlist.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	if len(b) > 0 {
		err := json.Unmarshal(b, &config)
		if err != nil {
			return 0, err
		}
	}
	if config.PostsPerPage <= 0 {
		config.PostsPerPage = 100
	}
	if databaseFS, ok := siteGen.fsys.(*DatabaseFS); ok {
		count, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
				" AND NOT is_dir" +
				" AND file_path LIKE '%.md'",
			Values: []any{
				sq.StringParam("parent", path.Join(siteGen.sitePrefix, "posts", category)),
			},
		}, func(row *sq.Row) int {
			return row.Int("COUNT(*)")
		})
		if err != nil {
			return 0, err
		}
		lastPage := int(math.Ceil(float64(count) / float64(config.PostsPerPage)))
		group, groupctx := errgroup.WithContext(ctx)
		group.Go(func() (err error) {
			defer func() {
				if v := recover(); v != nil {
					err = fmt.Errorf("panic: " + string(debug.Stack()))
				}
			}()
			filePaths, err := sq.FetchAll(groupctx, databaseFS.DB, sq.Query{
				Dialect: databaseFS.Dialect,
				Format: "SELECT {*}" +
					" FROM files" +
					" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
					" AND is_dir",
				Values: []any{
					sq.StringParam("parent", path.Join(siteGen.sitePrefix, "output/posts", category)),
				},
			}, func(row *sq.Row) string {
				return row.String("file_path")
			})
			if err != nil {
				return err
			}
			subgroup, subctx := errgroup.WithContext(groupctx)
			for _, filePath := range filePaths {
				filePath := filePath
				n, err := strconv.ParseInt(path.Base(filePath), 10, 64)
				if err != nil {
					continue
				}
				if int(n) <= lastPage {
					continue
				}
				subgroup.Go(func() (err error) {
					defer func() {
						if v := recover(); v != nil {
							err = fmt.Errorf("panic: " + string(debug.Stack()))
						}
					}()
					err = databaseFS.WithContext(subctx).RemoveAll(filePath)
					if err != nil {
						return err
					}
					return nil
				})
			}
			err = subgroup.Wait()
			if err != nil {
				return err
			}
			return nil
		})
		cursor, err := sq.FetchCursor(groupctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format: "SELECT {*}" +
				" FROM files" +
				" WHERE parent_id = (SELECT file_id FROM files WHERE file_path = {parent})" +
				" AND NOT is_dir" +
				" AND file_path LIKE '%.md'" +
				" ORDER BY file_path DESC",
			Values: []any{
				sq.StringParam("parent", path.Join(siteGen.sitePrefix, "posts", category)),
			},
		}, func(row *sq.Row) Post {
			var post Post
			post.Category = category
			name := path.Base(row.String("file_path"))
			post.Name = strings.TrimSuffix(name, path.Ext(name))
			post.CreationTime = row.Time("creation_time")
			post.ModificationTime = row.Time("mod_time")
			post.text = row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "text")
			return post
		})
		if err != nil {
			return 0, err
		}
		defer cursor.Close()
		page := 1
		batch := make([]Post, 0, config.PostsPerPage)
		for cursor.Next() {
			post, err := cursor.Result()
			if err != nil {
				return int64(page), err
			}
			timestampPrefix, _, _ := strings.Cut(post.Name, "-")
			if len(timestampPrefix) > 0 && len(timestampPrefix) <= 8 {
				b, err := base32Encoding.DecodeString(fmt.Sprintf("%08s", timestampPrefix))
				if len(b) == 5 && err == nil {
					var timestamp [8]byte
					copy(timestamp[len(timestamp)-5:], b)
					post.CreationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
				}
			}
			batch = append(batch, post)
			if len(batch) >= config.PostsPerPage {
				currentPage := page
				page++
				posts := slices.Clone(batch)
				batch = batch[:0]
				group.Go(func() (err error) {
					defer func() {
						if v := recover(); v != nil {
							err = fmt.Errorf("panic: " + string(debug.Stack()))
						}
					}()
					return siteGen.GeneratePostListPage(groupctx, category, tmpl, lastPage, currentPage, posts)
				})
			}
		}
		err = cursor.Close()
		if err != nil {
			return int64(page), err
		}
		if len(batch) > 0 {
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				return siteGen.GeneratePostListPage(groupctx, category, tmpl, lastPage, page, batch)
			})
		}
		err = group.Wait()
		if err != nil {
			return int64(page), err
		}
		if page == 1 && len(batch) == 0 {
			err := siteGen.GeneratePostListPage(ctx, category, tmpl, 1, 1, nil)
			if err != nil {
				return int64(page), err
			}
		}
		return int64(page), nil
	}
	dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(path.Join(siteGen.sitePrefix, "posts", category))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}
		if !strings.HasSuffix(dirEntry.Name(), ".md") {
			continue
		}
		dirEntries[n] = dirEntry
		n++
	}
	dirEntries = dirEntries[:n]
	slices.Reverse(dirEntries)
	lastPage := int(math.Ceil(float64(len(dirEntries)) / float64(config.PostsPerPage)))
	group, groupctx := errgroup.WithContext(ctx)
	group.Go(func() (err error) {
		defer func() {
			if v := recover(); v != nil {
				err = fmt.Errorf("panic: " + string(debug.Stack()))
			}
		}()
		dirEntries, err := siteGen.fsys.WithContext(groupctx).ReadDir(path.Join(siteGen.sitePrefix, "output/posts", category))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		subgroup, subctx := errgroup.WithContext(groupctx)
		for _, dirEntry := range dirEntries {
			dirEntry := dirEntry
			if !dirEntry.IsDir() {
				continue
			}
			n, err := strconv.ParseInt(dirEntry.Name(), 10, 64)
			if err != nil {
				continue
			}
			if int(n) <= lastPage {
				continue
			}
			subgroup.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				return siteGen.fsys.WithContext(subctx).RemoveAll(path.Join(siteGen.sitePrefix, "output/posts", category, strconv.FormatInt(n, 10)))
			})
		}
		err = subgroup.Wait()
		if err != nil {
			return err
		}
		return nil
	})
	page := 1
	batch := make([]Post, 0, config.PostsPerPage)
	var absoluteDir string
	if dirFS, ok := siteGen.fsys.(*DirFS); ok {
		absoluteDir = path.Join(dirFS.RootDir, siteGen.sitePrefix, "posts", category)
	}
	for _, dirEntry := range dirEntries {
		fileInfo, err := dirEntry.Info()
		if err != nil {
			return int64(page), err
		}
		name := fileInfo.Name()
		creationTime := CreationTime(path.Join(absoluteDir, name), fileInfo)
		timestampPrefix, _, _ := strings.Cut(name, "-")
		if len(timestampPrefix) > 0 && len(timestampPrefix) <= 8 {
			b, err := base32Encoding.DecodeString(fmt.Sprintf("%08s", timestampPrefix))
			if len(b) == 5 && err == nil {
				var timestamp [8]byte
				copy(timestamp[len(timestamp)-5:], b)
				creationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
			}
		}
		batch = append(batch, Post{
			Category:         category,
			Name:             strings.TrimSuffix(name, path.Ext(name)),
			CreationTime:     creationTime,
			ModificationTime: fileInfo.ModTime(),
		})
		if len(batch) >= config.PostsPerPage {
			currentPage := page
			page++
			posts := slices.Clone(batch)
			batch = batch[:0]
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				return siteGen.GeneratePostListPage(groupctx, category, tmpl, lastPage, currentPage, posts)
			})
		}
	}
	if len(batch) > 0 {
		group.Go(func() (err error) {
			defer func() {
				if v := recover(); v != nil {
					err = fmt.Errorf("panic: " + string(debug.Stack()))
				}
			}()
			return siteGen.GeneratePostListPage(groupctx, category, tmpl, lastPage, page, batch)
		})
	}
	err = group.Wait()
	if err != nil {
		return int64(page), err
	}
	if page == 1 && len(batch) == 0 {
		err := siteGen.GeneratePostListPage(ctx, category, tmpl, 1, 1, []Post{})
		if err != nil {
			return int64(page), err
		}
	}
	return int64(page), nil
}

func (siteGen *SiteGenerator) GeneratePostListPage(ctx context.Context, category string, tmpl *template.Template, lastPage, currentPage int, posts []Post) error {
	groupA, groupctxA := errgroup.WithContext(ctx)
	for i := range posts {
		i := i
		groupA.Go(func() error {
			if posts[i].text != nil {
				defer func() {
					if len(posts[i].text) <= maxPoolableBufferCapacity {
						posts[i].text = posts[i].text[:0]
						bufPool.Put(bytes.NewBuffer(posts[i].text))
						posts[i].text = nil
					}
				}()
			} else {
				file, err := siteGen.fsys.WithContext(groupctxA).Open(path.Join(siteGen.sitePrefix, "posts", category, posts[i].Name+".md"))
				if err != nil {
					return err
				}
				defer file.Close()
				buf := bufPool.Get().(*bytes.Buffer)
				defer func() {
					if buf.Cap() <= maxPoolableBufferCapacity {
						buf.Reset()
						bufPool.Put(buf)
						posts[i].text = nil
					}
				}()
				_, err = buf.ReadFrom(file)
				if err != nil {
					return err
				}
				posts[i].text = buf.Bytes()
			}
			var line []byte
			remainder := posts[i].text
			for len(remainder) > 0 {
				line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				if posts[i].Title == "" {
					posts[i].Title = stripMarkdownStyles(siteGen.markdown, line)
					continue
				}
				if posts[i].Preview == "" {
					posts[i].Preview = stripMarkdownStyles(siteGen.markdown, line)
					posts[i].HasMore = len(bytes.TrimSpace(remainder)) > 0
					continue
				}
				break
			}
			if posts[i].Title == "" {
				posts[i].Title = posts[i].Name
			}
			var b strings.Builder
			err := siteGen.markdown.Convert(posts[i].text, &b)
			if err != nil {
				return err
			}
			posts[i].Content = template.HTML(b.String())
			return nil
		})
	}
	err := groupA.Wait()
	if err != nil {
		return err
	}
	postListData := PostListData{
		Site:       siteGen.Site,
		Category:   category,
		Pagination: NewPagination(currentPage, lastPage, 9),
		Posts:      posts,
	}
	outputDir := path.Join(siteGen.sitePrefix, "output/posts", postListData.Category)
	var outputFile string
	if currentPage == 1 {
		outputFile = path.Join(outputDir, "index.html")
	} else {
		outputFile = path.Join(outputDir, strconv.Itoa(currentPage), "index.html")
	}
	groupB, groupctxB := errgroup.WithContext(ctx)
	groupB.Go(func() error {
		writer, err := siteGen.fsys.WithContext(groupctxB).OpenWriter(outputFile, 0644)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			err := siteGen.fsys.WithContext(groupctxB).MkdirAll(path.Dir(outputFile), 0755)
			if err != nil {
				return err
			}
			writer, err = siteGen.fsys.WithContext(groupctxB).OpenWriter(outputFile, 0644)
			if err != nil {
				return err
			}
		}
		defer writer.Close()
		atomPath := "/" + path.Join("posts", category) + "/index.atom"
		_, err = io.WriteString(writer, "<!DOCTYPE html>\n"+
			"<html lang='"+template.HTMLEscapeString(siteGen.Site.Lang)+"'>\n"+
			"<meta charset='utf-8'>\n"+
			"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"+
			"<link rel='icon' href='"+template.HTMLEscapeString(string(siteGen.Site.Favicon))+"'>\n"+
			"<link rel='alternate' href='"+template.HTMLEscapeString(atomPath)+"' type='application/atom+xml'>\n",
		)
		if err != nil {
			return err
		}
		_, isDatabaseFS := siteGen.fsys.(*DatabaseFS)
		if siteGen.imgDomain != "" && isDatabaseFS {
			pipeReader, pipeWriter := io.Pipe()
			result := make(chan error, 1)
			go func() {
				defer func() {
					if v := recover(); v != nil {
						result <- fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				result <- siteGen.rewriteURLs(writer, pipeReader, "")
			}()
			err = tmpl.Execute(pipeWriter, &postListData)
			if err != nil {
				return NewTemplateError(err)
			}
			pipeWriter.Close()
			err = <-result
			if err != nil {
				return err
			}
		} else {
			err = tmpl.Execute(writer, &postListData)
			if err != nil {
				return NewTemplateError(err)
			}
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		return nil
	})
	if currentPage == 1 {
		groupB.Go(func() error {
			outputFile := path.Join(outputDir, "1/index.html")
			writer, err := siteGen.fsys.WithContext(groupctxB).OpenWriter(outputFile, 0644)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				err := siteGen.fsys.WithContext(groupctxB).MkdirAll(path.Dir(outputFile), 0755)
				if err != nil {
					return err
				}
				writer, err = siteGen.fsys.WithContext(groupctxB).OpenWriter(outputFile, 0644)
				if err != nil {
					return err
				}
			}
			defer writer.Close()
			urlPath := "/" + path.Join("posts", category) + "/"
			_, err = io.WriteString(writer, "<!DOCTYPE html>\n"+
				"<html lang='"+template.HTMLEscapeString(siteGen.Site.Lang)+"'>\n"+
				"<meta charset='utf-8'>\n"+
				"<meta name='viewport' content='width=device-width, initial-scale=1'>\n"+
				"<meta http-equiv='refresh' content='0; url="+template.HTMLEscapeString(urlPath)+"'>\n"+
				"<title>redirect to "+urlPath+"</title>\n"+
				"<p>redirect to <a href='"+template.HTMLEscapeString(urlPath)+"'>"+urlPath+"</a></p>\n",
			)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			return nil
		})
		groupB.Go(func() error {
			scheme := "https://"
			var contentDomain string
			if strings.Contains(siteGen.sitePrefix, ".") {
				contentDomain = siteGen.sitePrefix
			} else {
				if !siteGen.contentDomainHTTPS {
					scheme = "http://"
				}
				if siteGen.sitePrefix != "" {
					contentDomain = strings.TrimPrefix(siteGen.sitePrefix, "@") + "." + siteGen.contentDomain
				} else {
					contentDomain = siteGen.contentDomain
				}
			}
			feed := AtomFeed{
				Xmlns:   "http://www.w3.org/2005/Atom",
				ID:      scheme + contentDomain,
				Title:   siteGen.Site.Title,
				Updated: time.Now().UTC().Format("2006-01-02 15:04:05Z"),
				Link: []AtomLink{{
					Href: scheme + contentDomain + "/" + path.Join("posts", postListData.Category) + "/index.atom",
					Rel:  "self",
				}, {
					Href: scheme + contentDomain + "/" + path.Join("posts", postListData.Category) + "/",
					Rel:  "alternate",
				}},
				Entry: make([]AtomEntry, len(postListData.Posts)),
			}
			for i, post := range postListData.Posts {
				// ID: tag:bokwoon.nbrew.io,yyyy-mm-dd:1jjdz28
				var postID string
				timestampPrefix, _, _ := strings.Cut(post.Name, "-")
				if len(timestampPrefix) > 0 && len(timestampPrefix) <= 8 {
					b, err := base32Encoding.DecodeString(fmt.Sprintf("%08s", timestampPrefix))
					if len(b) == 5 && err == nil {
						var timestamp [8]byte
						copy(timestamp[len(timestamp)-5:], b)
						post.CreationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
						postID = "tag:" + contentDomain + "," + post.CreationTime.UTC().Format("2006-01-02") + ":" + timestampPrefix
					}
				}
				if postID == "" {
					postID = scheme + contentDomain + "/" + path.Join("posts", post.Category, post.Name) + "/"
				}
				feed.Entry[i] = AtomEntry{
					ID:        postID,
					Title:     post.Title,
					Published: post.CreationTime.UTC().Format("2006-01-02 15:04:05Z"),
					Updated:   post.ModificationTime.UTC().Format("2006-01-02 15:04:05Z"),
					Link: []AtomLink{{
						Href: scheme + contentDomain + "/" + path.Join("posts", post.Category, post.Name) + "/",
						Rel:  "alternate",
					}},
					Summary: AtomText{
						Type:    "text",
						Content: string(post.Preview),
					},
					Content: AtomCDATA{
						Type:    "html",
						Content: strings.ReplaceAll(string(post.Content), "]]>", "]]]]><![CDATA[>"), // https://stackoverflow.com/a/36331725
					},
				}
			}
			writer, err := siteGen.fsys.WithContext(groupctxB).OpenWriter(path.Join(outputDir, "index.atom"), 0644)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				err := siteGen.fsys.WithContext(groupctxB).MkdirAll(outputDir, 0755)
				if err != nil {
					return err
				}
				writer, err = siteGen.fsys.WithContext(groupctxB).OpenWriter(path.Join(outputDir, "index.atom"), 0644)
				if err != nil {
					return err
				}
			}
			defer writer.Close()
			_, err = writer.Write([]byte(xml.Header))
			if err != nil {
				return err
			}
			encoder := xml.NewEncoder(writer)
			encoder.Indent("", "  ")
			err = encoder.Encode(&feed)
			if err != nil {
				return err
			}
			err = writer.Close()
			if err != nil {
				return err
			}
			return nil
		})
	}
	err = groupB.Wait()
	if err != nil {
		return err
	}
	return nil
}

type TemplateError struct {
	Name         string `json:"name"`
	Line         int    `json:"line"`
	ErrorMessage string `json:"errorMessage"`
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
	return TemplateError{
		Name:         templateName,
		Line:         lineNo,
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

func (siteGen *SiteGenerator) rewriteURLs(writer io.Writer, reader io.Reader, urlPath string) error {
	tokenizer := html.NewTokenizer(reader)
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return nil
			}
			return err
		case html.TextToken:
			_, err := writer.Write(tokenizer.Text())
			if err != nil {
				return err
			}
		case html.DoctypeToken:
			for _, b := range [...][]byte{
				[]byte("<!DOCTYPE "), tokenizer.Text(), []byte(">"),
			} {
				_, err := writer.Write(b)
				if err != nil {
					return err
				}
			}
		case html.CommentToken:
			for _, b := range [...][]byte{
				[]byte("<!--"), tokenizer.Text(), []byte("-->"),
			} {
				_, err := writer.Write(b)
				if err != nil {
					return err
				}
			}
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			switch tokenType {
			case html.StartTagToken, html.SelfClosingTagToken:
				_, err := writer.Write([]byte("<"))
				if err != nil {
					return err
				}
			case html.EndTagToken:
				_, err := writer.Write([]byte("</"))
				if err != nil {
					return err
				}
			}
			var key, val, rewrittenVal []byte
			name, moreAttr := tokenizer.TagName()
			_, err := writer.Write(name)
			if err != nil {
				return err
			}
			isImgTag := bytes.Equal(name, []byte("img"))
			isAnchorTag := bytes.Equal(name, []byte("a"))
			for moreAttr {
				key, val, moreAttr = tokenizer.TagAttr()
				rewrittenVal = val
				if (isImgTag && bytes.Equal(key, []byte("src"))) || (isAnchorTag && bytes.Equal(key, []byte("href"))) {
					uri, err := url.Parse(string(val))
					if err == nil && uri.Scheme == "" && uri.Host == "" {
						switch path.Ext(uri.Path) {
						case ".jpeg", ".jpg", ".png", ".webp", ".gif":
							uri.Scheme = ""
							uri.Host = siteGen.imgDomain
							if strings.HasPrefix(uri.Path, "/") {
								filePath := path.Join(siteGen.sitePrefix, "output", uri.Path)
								if fileID, ok := siteGen.imgFileIDs[filePath]; ok {
									uri.Path = "/" + fileID.String() + path.Ext(filePath)
									rewrittenVal = []byte(uri.String())
								}
							} else {
								if urlPath != "" {
									filePath := path.Join(siteGen.sitePrefix, "output", urlPath, uri.Path)
									if fileID, ok := siteGen.imgFileIDs[filePath]; ok {
										uri.Path = "/" + fileID.String() + path.Ext(filePath)
										rewrittenVal = []byte(uri.String())
									}
								}
							}
						}
					}
				}
				for _, b := range [...][]byte{
					[]byte(` `), key, []byte(`="`), rewrittenVal, []byte(`"`),
				} {
					_, err := writer.Write(b)
					if err != nil {
						return err
					}
				}
			}
			switch tokenType {
			case html.StartTagToken, html.EndTagToken:
				_, err = writer.Write([]byte(">"))
				if err != nil {
					return err
				}
			case html.SelfClosingTagToken:
				_, err = writer.Write([]byte("/>"))
				if err != nil {
					return err
				}
			}
		}
	}
}

var funcMap = map[string]any{
	"join":                  path.Join,
	"base":                  path.Base,
	"ext":                   path.Ext,
	"hasPrefix":             strings.HasPrefix,
	"hasSuffix":             strings.HasSuffix,
	"trimPrefix":            strings.TrimPrefix,
	"trimSuffix":            strings.TrimSuffix,
	"trimSpace":             strings.TrimSpace,
	"humanReadableFileSize": humanReadableFileSize,
	"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
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

type Pagination struct {
	First    string
	Previous string
	Current  string
	Next     string
	Last     string
	Numbers  []string
}

func NewPagination(currentPage, lastPage, visiblePages int) Pagination {
	const numConsecutiveNeighbours = 2
	if visiblePages%2 == 0 {
		panic("even number of visiblePages")
	}
	minVisiblePages := (numConsecutiveNeighbours * 2) + 1
	if visiblePages < minVisiblePages {
		panic("visiblePages cannot be lower than " + strconv.Itoa(minVisiblePages))
	}
	pagination := Pagination{
		First:   "1",
		Current: strconv.Itoa(currentPage),
		Last:    strconv.Itoa(lastPage),
	}
	previous := currentPage - 1
	if previous >= 1 {
		pagination.Previous = strconv.Itoa(previous)
	}
	next := currentPage + 1
	if next <= lastPage {
		pagination.Next = strconv.Itoa(next)
	}
	// If there are fewer pages than visible pages, iterate through all the
	// page numbers.
	if lastPage <= visiblePages {
		pagination.Numbers = make([]string, 0, lastPage)
		for page := 1; page <= lastPage; page++ {
			pagination.Numbers = append(pagination.Numbers, strconv.Itoa(page))
		}
		return pagination
	}
	// Slots corresponds to the available slots in pagination.Numbers, storing
	// the page numbers as integers. They will be converted to strings later.
	slots := make([]int, visiblePages)
	// A unit is a tenth of the maximum number of pages. The rationale is that
	// users should have to paginate at most 10 such units to get from start to
	// end, no matter how many pages there are.
	unit := lastPage / 10
	if currentPage-1 < len(slots)>>1 {
		// If there are fewer pages on the left than half of the slots, the
		// current page will skew more towards the left. We fill in consecutive
		// page numbers from left to right, then fill in the remaining slots.
		numConsecutive := (currentPage - 1) + 1 + numConsecutiveNeighbours
		consecutiveStart := 0
		consecutiveEnd := numConsecutive - 1
		page := 1
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		// The last slot is always the last page.
		slots[len(slots)-1] = lastPage
		// Fill in the remaining slots with either an exponentially changing or
		// linearly changing number depending on which is more appropriate.
		remainingSlots := slots[consecutiveEnd+1 : len(slots)-1]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else if lastPage-currentPage < len(slots)>>1 {
		// If there are fewer pages on the right than half of the slots, the
		// current page will skew more towards the right. We fill in
		// consecutive page numbers from the right to left, then fill in the
		// remaining slots.
		numConsecutive := (lastPage - currentPage) + 1 + numConsecutiveNeighbours
		consecutiveStart := len(slots) - 1
		consecutiveEnd := len(slots) - numConsecutive
		page := lastPage
		for i := consecutiveStart; i >= consecutiveEnd; i-- {
			slots[i] = page
			page -= 1
		}
		// The first slot is always the first page.
		slots[0] = 1
		// Fill in the remaining slots with either an exponentially changing or
		// linearly changing number depending on which is more appropriate.
		remainingSlots := slots[1:consecutiveEnd]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveEnd; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else {
		// If we reach here, it means the current page is directly in the
		// center the slots. Fill in the consecutive band of numbers around the
		// center, then fill in the remaining slots to the left and to the
		// right.
		consecutiveStart := len(slots)>>1 - numConsecutiveNeighbours
		consecutiveEnd := len(slots)>>1 + numConsecutiveNeighbours
		page := currentPage - numConsecutiveNeighbours
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		// The first slot is always the first page.
		slots[0] = 1
		// The last slot is always the last page.
		slots[len(slots)-1] = lastPage
		// Fill in the remaining slots on the left with either an exponentially
		// changing or linearly changing number depending on which is more
		// appropriate.
		remainingSlots := slots[1:consecutiveStart]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveStart; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
		// Fill in the remaining slots on the right with either an exponentially
		// changing or linearly changing number depending on which is more
		// appropriate.
		remainingSlots = slots[consecutiveEnd+1 : len(slots)-1]
		delta = numConsecutiveNeighbours + len(remainingSlots)
		shift = 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	}
	// Convert the page numbers in the slots to strings.
	pagination.Numbers = make([]string, len(slots))
	for i, num := range slots {
		pagination.Numbers[i] = strconv.Itoa(num)
	}
	return pagination
}

func (p Pagination) All() []string {
	lastPage, err := strconv.Atoi(p.Last)
	if err != nil {
		return nil
	}
	numbers := make([]string, 0, lastPage)
	for page := 1; page <= lastPage; page++ {
		numbers = append(numbers, strconv.Itoa(page))
	}
	return numbers
}

type AtomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Xmlns   string      `xml:"xmlns,attr"`
	ID      string      `xml:"id"`
	Title   string      `xml:"title"`
	Updated string      `xml:"updated"`
	Link    []AtomLink  `xml:"link"`
	Entry   []AtomEntry `xml:"entry"`
}

type AtomEntry struct {
	ID        string     `xml:"id"`
	Title     string     `xml:"title"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
	Link      []AtomLink `xml:"link"`
	Summary   AtomText   `xml:"summary"`
	Content   AtomCDATA  `xml:"content"`
}

type AtomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

type AtomText struct {
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

type AtomCDATA struct {
	Type    string `xml:"type,attr"`
	Content string `xml:",cdata"`
}

func (siteGen *SiteGenerator) PostTemplate(ctx context.Context, category string) (*template.Template, error) {
	if strings.Contains(category, "/") {
		return nil, fmt.Errorf("invalid post category")
	}
	var text string
	var found bool
	if databaseFS, ok := siteGen.fsys.(*DatabaseFS); ok {
		result, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", path.Join(siteGen.sitePrefix, "posts", category, "post.html")),
			},
		}, func(row *sq.Row) sql.NullString {
			return row.NullString("text")
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		text = result.String
		found = result.Valid
	} else {
		file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "posts", category, "post.html"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		} else {
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return nil, err
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return nil, err
			}
			err = file.Close()
			if err != nil {
				return nil, err
			}
			text = b.String()
			found = true
		}
	}
	if !found {
		file, err := RuntimeFS.Open("embed/post.html")
		if err != nil {
			return nil, err
		}
		fileInfo, err := file.Stat()
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			return nil, err
		}
		err = file.Close()
		if err != nil {
			return nil, err
		}
		text = b.String()
	}
	tmpl, err := siteGen.ParseTemplate(ctx, path.Join("posts", category, "post.html"), text)
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}

func (siteGen *SiteGenerator) PostListTemplate(ctx context.Context, category string) (*template.Template, error) {
	if strings.Contains(category, "/") {
		return nil, fmt.Errorf("invalid post category")
	}
	var err error
	var text string
	var found bool
	if databaseFS, ok := siteGen.fsys.(*DatabaseFS); ok {
		result, err := sq.FetchOne(ctx, databaseFS.DB, sq.Query{
			Dialect: databaseFS.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", path.Join(siteGen.sitePrefix, "posts", category, "postlist.html")),
			},
		}, func(row *sq.Row) sql.NullString {
			return row.NullString("text")
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		text = result.String
		found = result.Valid
	} else {
		file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "posts", category, "postlist.html"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		} else {
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				return nil, err
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return nil, err
			}
			err = file.Close()
			if err != nil {
				return nil, err
			}
			text = b.String()
			found = true
		}
	}
	if !found {
		file, err := RuntimeFS.Open("embed/postlist.html")
		if err != nil {
			return nil, err
		}
		fileInfo, err := file.Stat()
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			return nil, err
		}
		err = file.Close()
		if err != nil {
			return nil, err
		}
		text = b.String()
	}
	tmpl, err := siteGen.ParseTemplate(ctx, path.Join("posts", category, "postlist.html"), text)
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}
