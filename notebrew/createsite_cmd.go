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
	"path/filepath"
	"strings"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
)

type CreatesiteCmd struct {
	Notebrew *nb10.Notebrew
	SiteName string
}

func CreatesiteCommand(configDir string, nbrew *nb10.Notebrew, args ...string) (*CreatesiteCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("%s has not been configured: to fix, run `notebrew config database.dialect sqlite`", filepath.Join(configDir, "database.json"))
	}
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
		validationError, err := cmd.validateSiteName(cmd.SiteName)
		if err != nil {
			return nil, err
		}
		if validationError != "" {
			fmt.Println(validationError)
			continue
		}
		break
	}
	return &cmd, nil
}

func (cmd *CreatesiteCmd) Run() error {
	validationError, err := cmd.validateSiteName(cmd.SiteName)
	if err != nil {
		return err
	}
	if validationError != "" {
		return fmt.Errorf(validationError)
	}
	var sitePrefix string
	if strings.Contains(cmd.SiteName, ".") {
		sitePrefix = cmd.SiteName
	} else if cmd.SiteName != "" {
		sitePrefix = "@" + cmd.SiteName
	}
	err = cmd.Notebrew.FS.Mkdir(sitePrefix, 0755)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	dirs := []string{
		"notes",
		"output",
		"output/images",
		"output/themes",
		"pages",
		"posts",
		"system",
	}
	for _, dir := range dirs {
		err = cmd.Notebrew.FS.Mkdir(path.Join(sitePrefix, dir), 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	siteID := nb10.NewID()
	_, err = sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "INSERT INTO site (site_id, site_name) VALUES ({siteID}, {siteName})",
		Values: []any{
			sq.UUIDParam("siteID", siteID),
			sq.StringParam("siteName", cmd.SiteName),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (cmd *CreatesiteCmd) validateSiteName(siteName string) (validationError string, err error) {
	if siteName == "" {
		return "site name cannot be empty", nil
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
		return "site name unavailable", nil
	}
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
		return "site name unavailable", nil
	}
	return "", nil
}
