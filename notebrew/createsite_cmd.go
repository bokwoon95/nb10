package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/sync/errgroup"
)

type CreatesiteCmd struct {
	Notebrew *nb10.Notebrew
	SiteName string
}

func CreatesiteCommand(configDir string, nbrew *nb10.Notebrew, args ...string) (*CreatesiteCmd, error) {
	var cmd CreatesiteCmd
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Usage = func() {
		fmt.Fprintln(flagset.Output(), `Usage:
  lorem ipsum dolor sit amet
  consectetur adipiscing elit`)
	}
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	args = flagset.Args()
	if len(args) > 1 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(args[1:], " "))
	}
	if len(args) == 1 {
		cmd.SiteName = args[0]
		return &cmd, nil
	}
	fmt.Println("Press Ctrl+C to exit.")
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Site name: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		cmd.SiteName = strings.TrimSpace(text)
		errmsg, err := cmd.validateSiteName(cmd.SiteName)
		if err != nil {
			return nil, err
		}
		if errmsg != "" {
			fmt.Println(errmsg)
			continue
		}
		break
	}
	return &cmd, nil
}

func (cmd *CreatesiteCmd) Run() error {
	errmsg, err := cmd.validateSiteName(cmd.SiteName)
	if err != nil {
		return err
	}
	if errmsg != "" {
		return fmt.Errorf(errmsg)
	}
	var sitePrefix string
	if strings.Contains(cmd.SiteName, ".") {
		sitePrefix = cmd.SiteName
	} else if cmd.SiteName != "" {
		sitePrefix = "@" + cmd.SiteName
	}
	if cmd.Notebrew.DB != nil {
		_, err = sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format:  "INSERT INTO site (site_id, site_name) VALUES ({siteID}, {siteName})",
			Values: []any{
				sq.UUIDParam("siteID", nb10.NewID()),
				sq.StringParam("siteName", cmd.SiteName),
			},
		})
		if err != nil {
			return err
		}
	}
	err = cmd.Notebrew.FS.Mkdir(sitePrefix, 0755)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	dirs := []string{
		"notes",
		"output",
		"output/themes",
		"pages",
		"posts",
	}
	for _, dir := range dirs {
		err = cmd.Notebrew.FS.Mkdir(path.Join(sitePrefix, dir), 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	siteGen, err := nb10.NewSiteGenerator(context.Background(), cmd.Notebrew.FS, sitePrefix, cmd.Notebrew.ContentDomain, cmd.Notebrew.ImgDomain)
	if err != nil {
		return err
	}
	group, groupctx := errgroup.WithContext(context.Background())
	group.Go(func() error {
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/site.json")
		if err != nil {
			return err
		}
		writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "site.json"), 0644)
		if err != nil {
			return err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		return nil
	})
	group.Go(func() error {
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/postlist.json")
		if err != nil {
			return err
		}
		writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/postlist.json"), 0644)
		if err != nil {
			return err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		return nil
	})
	group.Go(func() error {
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/index.html")
		if err != nil {
			return err
		}
		writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/index.html"), 0644)
		if err != nil {
			return err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		err = siteGen.GeneratePage(groupctx, "pages/index.html", string(b))
		if err != nil {
			return err
		}
		return nil
	})
	group.Go(func() error {
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/404.html")
		if err != nil {
			return err
		}
		writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "pages/404.html"), 0644)
		if err != nil {
			return err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		err = siteGen.GeneratePage(groupctx, "pages/404.html", string(b))
		if err != nil {
			return err
		}
		return nil
	})
	group.Go(func() error {
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/post.html")
		if err != nil {
			return err
		}
		writer, err := cmd.Notebrew.FS.WithContext(groupctx).OpenWriter(path.Join(sitePrefix, "posts/post.html"), 0644)
		if err != nil {
			return err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		return nil
	})
	group.Go(func() error {
		b, err := fs.ReadFile(nb10.RuntimeFS, "embed/postlist.html")
		if err != nil {
			return err
		}
		writer, err := cmd.Notebrew.FS.OpenWriter(path.Join(sitePrefix, "posts/postlist.html"), 0644)
		if err != nil {
			return err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
		tmpl, err := siteGen.PostListTemplate(context.Background(), "")
		if err != nil {
			return err
		}
		_, err = siteGen.GeneratePostList(context.Background(), "", tmpl)
		if err != nil {
			return err
		}
		return nil
	})
	err = group.Wait()
	if err != nil {
		return err
	}
	return nil
}

func (cmd *CreatesiteCmd) validateSiteName(siteName string) (errmsg string, err error) {
	if siteName == "" {
		return "cannot be empty", nil
	}
	if siteName == "www" || siteName == "img" || siteName == "video" || siteName == "cdn" {
		return "unavailable", nil
	}
	for _, char := range siteName {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '.' {
			return "only lowercase letters, numbers, hyphen and dot allowed", nil
		}
	}
	if len(siteName) > 30 {
		return "cannot exceed 30 characters", nil
	}
	var sitePrefix string
	if strings.Contains(siteName, ".") {
		sitePrefix = siteName
	} else {
		sitePrefix = "@" + siteName
	}
	fileInfo, err := fs.Stat(cmd.Notebrew.FS, sitePrefix)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if fileInfo != nil {
		return "unavailable", nil
	}
	if cmd.Notebrew.DB != nil {
		exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format:  "SELECT 1 FROM site WHERE site_name = {siteName}",
			Values: []any{
				sq.StringParam("siteName", siteName),
			},
		})
		if err != nil {
			return "", err
		}
		if exists {
			return "unavailable", nil
		}
	}
	return "", nil
}
