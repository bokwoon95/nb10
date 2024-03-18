package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
)

type DeletesiteCmd struct {
	Notebrew *nb10.Notebrew
	SiteName string
}

func DeletesiteCommand(nbrew *nb10.Notebrew, args ...string) (*DeletesiteCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("no database configured: to fix, run `notebrew config database.dialect sqlite`")
	}
	var cmd DeletesiteCmd
	cmd.Notebrew = nbrew
	var confirm bool
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.BoolVar(&confirm, "confirm", false, "")
	flagset.Usage = func() {
		fmt.Fprintln(flagset.Output(), `Usage:
  lorem ipsum dolor sit amet
  consectetur adipiscing elit
Flags:`)
		flagset.PrintDefaults()
	}
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	args = flagset.Args()
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			err := flagset.Parse(args[i:])
			if err != nil {
				return nil, err
			}
			args = args[:i]
			break
		}
	}
	if len(args) > 1 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(args[1:], " "))
	}
	if len(args) == 1 {
		cmd.SiteName = args[0]
		if confirm {
			return &cmd, nil
		}
		validationError, err := cmd.validateSiteName(cmd.SiteName)
		if err != nil {
			return nil, err
		}
		if validationError != "" {
			return nil, fmt.Errorf(validationError)
		}
	}
	fmt.Println("Press Ctrl+C to exit.")
	reader := bufio.NewReader(os.Stdin)
	if len(args) == 0 {
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
	}
	if !confirm {
		for {
			fmt.Printf("Are you sure you wish to delete site %q? This action is permanent and cannot be undone. All files within the site will be deleted.\n", cmd.SiteName)
			fmt.Printf("Please confirm the site name that you wish to delete (%s): ", cmd.SiteName)
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			text = strings.TrimSpace(text)
			if text != cmd.SiteName {
				fmt.Println("site name does not match")
				continue
			}
			break
		}
	}
	return &cmd, nil
}

func (cmd *DeletesiteCmd) Run() error {
	validationError, err := cmd.validateSiteName(cmd.SiteName)
	if err != nil {
		return err
	}
	if validationError != "" {
		return fmt.Errorf(validationError)
	}
	if cmd.SiteName != "" {
		var sitePrefix string
		if strings.Contains(cmd.SiteName, ".") {
			sitePrefix = cmd.SiteName
		} else {
			sitePrefix = "@" + cmd.SiteName
		}
		err = cmd.Notebrew.FS.RemoveAll(sitePrefix)
		if err != nil {
			return err
		}
	}
	tx, err := cmd.Notebrew.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format: "DELETE FROM site_user WHERE EXISTS (" +
			"SELECT 1" +
			" FROM site" +
			" WHERE site.site_id = site_user.site_id" +
			" AND site.site_name = {siteName}" +
			")",
		Values: []any{
			sq.StringParam("siteName", cmd.SiteName),
		},
	})
	if err != nil {
		return err
	}
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "DELETE FROM site WHERE site_name = {siteName}",
		Values: []any{
			sq.StringParam("siteName", cmd.SiteName),
		},
	})
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (cmd DeletesiteCmd) validateSiteName(siteName string) (validationError string, err error) {
	if siteName == "" {
		return "site name cannot be empty", nil
	}
	if cmd.Notebrew.DB != nil {
		exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format:  "SELECT 1 FROM users WHERE username = {siteName}",
			Values: []any{
				sq.StringParam("siteName", siteName),
			},
		})
		if err != nil {
			return "", err
		}
		if exists {
			return "site is associated with a user, please use deleteuser instead", nil
		}
	}
	var sitePrefix string
	if strings.Contains(siteName, ".") {
		sitePrefix = siteName
	} else {
		sitePrefix = "@" + siteName
	}
	var existsInFS, existsInDB bool
	_, err = fs.Stat(cmd.Notebrew.FS, sitePrefix)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	} else {
		existsInFS = true
	}
	if cmd.Notebrew.DB != nil {
		existsInDB, err = sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format:  "SELECT 1 FROM site WHERE site_name = {siteName}",
			Values: []any{
				sq.StringParam("siteName", siteName),
			},
		})
		if err != nil {
			return "", err
		}
	}
	if !existsInFS && !existsInDB {
		return "site does not exist", nil
	}
	return "", nil
}
