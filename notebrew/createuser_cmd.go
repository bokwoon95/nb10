package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/mail"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/term"
)

type CreateuserCmd struct {
	Notebrew     *nb10.Notebrew
	Stdout       io.Writer
	Username     string
	Email        string
	PasswordHash string
}

func CreateuserCommand(nbrew *nb10.Notebrew, args ...string) (*CreateuserCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("no database configured: to fix, run `notebrew config database.dialect sqlite`")
	}
	var cmd CreateuserCmd
	cmd.Notebrew = nbrew
	var username sql.NullString
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("username", "", func(s string) error {
		username = sql.NullString{String: s, Valid: true}
		return nil
	})
	flagset.StringVar(&cmd.Email, "email", "", "")
	flagset.StringVar(&cmd.PasswordHash, "password-hash", "", "")
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	flagArgs := flagset.Args()
	if len(flagArgs) > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagArgs, " "))
	}
	cmd.Username = strings.TrimSpace(username.String)
	cmd.Email = strings.TrimSpace(cmd.Email)
	if username.Valid && cmd.Email != "" && cmd.PasswordHash != "" {
		return &cmd, nil
	}
	fmt.Println("Press Ctrl+C to exit.")
	reader := bufio.NewReader(os.Stdin)

	if !username.Valid {
		for {
			fmt.Print("Username (leave blank for the default user): ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			username.String = strings.TrimSpace(text)
			validationError, err := cmd.validateUsername(username.String)
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
	cmd.Username = username.String

	if cmd.Email == "" {
		for {
			fmt.Print("Email: ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			cmd.Email = strings.TrimSpace(text)
			validationError, err := cmd.validateEmail(cmd.Email)
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

	if cmd.PasswordHash == "" {
		for {
			fmt.Print("Password (will be hidden from view): ")
			password, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return nil, err
			}
			validationError, err := cmd.validatePassword(password)
			if err != nil {
				return nil, err
			}
			if validationError != "" {
				fmt.Println(validationError)
				continue
			}
			fmt.Print("Confirm password (will be hidden from view): ")
			confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return nil, err
			}
			if subtle.ConstantTimeCompare(password, confirmPassword) != 1 {
				fmt.Println("passwords do not match")
				continue
			}
			b, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			cmd.PasswordHash = string(b)
			break
		}
	}
	return &cmd, nil
}

func (cmd *CreateuserCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	validationError, err := cmd.validateUsername(cmd.Username)
	if err != nil {
		return err
	}
	if validationError != "" {
		return fmt.Errorf(validationError)
	}
	validationError, err = cmd.validateEmail(cmd.Email)
	if err != nil {
		return err
	}
	if validationError != "" {
		return fmt.Errorf(validationError)
	}

	if cmd.Username == "" {
	}

	var sitePrefix string
	if strings.Contains(cmd.Username, ".") {
		sitePrefix = cmd.Username
	} else if cmd.Username != "" {
		sitePrefix = "@" + cmd.Username
	}
	if sitePrefix != "" {
		err := cmd.Notebrew.FS.Mkdir(sitePrefix, 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
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

	siteID := nb10.NewID()
	userID := nb10.NewID()
	tx, err := cmd.Notebrew.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "INSERT INTO site (site_id, site_name) VALUES ({siteID}, {siteName})",
		Values: []any{
			sq.UUIDParam("siteID", siteID),
			sq.StringParam("siteName", cmd.Username),
		},
	})
	if err != nil {
		return err
	}
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format: "INSERT INTO users (user_id, username, email, password_hash)" +
			" VALUES ({userID}, {username}, {email}, {passwordHash})",
		Values: []any{
			sq.UUIDParam("userID", userID),
			sq.StringParam("username", cmd.Username),
			sq.StringParam("email", cmd.Email),
			sq.StringParam("passwordHash", cmd.PasswordHash),
		},
	})
	if err != nil {
		return err
	}
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "INSERT INTO site_user (site_id, user_id) VALUES ({siteID}, {userID})",
		Values: []any{
			sq.UUIDParam("siteID", siteID),
			sq.UUIDParam("userID", userID),
		},
	})
	if err != nil {
		return err
	}
	_, err = sq.Exec(context.Background(), tx, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "INSERT INTO site_owner (site_id, user_id) VALUES ({siteID}, {userID})",
		Values: []any{
			sq.UUIDParam("siteID", siteID),
			sq.UUIDParam("userID", userID),
		},
	})
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.Stdout, "1 user created")
	return nil
}

func (cmd *CreateuserCmd) validateUsername(username string) (validationError string, err error) {
	for _, char := range username {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return "username can only contain lowercase letters, numbers and hyphen", nil
		}
	}
	if username != "" {
		var sitePrefix string
		if strings.Contains(username, ".") {
			sitePrefix = username
		} else {
			sitePrefix = "@" + username
		}
		fileInfo, err := fs.Stat(cmd.Notebrew.FS, sitePrefix)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if fileInfo != nil {
			return "username already taken", nil
		}
	}
	exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "SELECT 1 FROM site WHERE site_name = {username}",
		Values: []any{
			sq.StringParam("username", username),
		},
	})
	if err != nil {
		return "", err
	}
	if exists {
		return "username already taken.", nil
	}
	return "", nil
}

func (cmd *CreateuserCmd) validateEmail(email string) (validationError string, err error) {
	if email == "" {
		return "email cannot be empty", nil
	}
	_, err = mail.ParseAddress(cmd.Email)
	if err != nil {
		return "invalid email address", nil
	}
	exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "SELECT 1 FROM users WHERE email = {email}",
		Values: []any{
			sq.StringParam("email", email),
		},
	})
	if err != nil {
		return "", err
	}
	if exists {
		return "email already used by an existing user account", nil
	}
	return "", nil
}

var getCommonPasswordHashes = sync.OnceValues(func() (map[string]struct{}, error) {
	commonPasswordHashes := make(map[string]struct{})
	file, err := nb10.RuntimeFS.Open("embed/top-10000-passwords.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	done := false
	for {
		if done {
			break
		}
		line, err := reader.ReadBytes('\n')
		done = err == io.EOF
		if err != nil && !done {
			panic(err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		hash := blake2b.Sum256([]byte(line))
		encodedHash := hex.EncodeToString(hash[:])
		commonPasswordHashes[encodedHash] = struct{}{}
	}
	return commonPasswordHashes, nil
})

func (cmd *CreateuserCmd) validatePassword(password []byte) (validationError string, err error) {
	if utf8.RuneCount(password) < 8 {
		return "password must be at least 8 characters", nil
	}
	commonPasswordHashes, err := getCommonPasswordHashes()
	if err != nil {
		return "", err
	}
	hash := blake2b.Sum256(password)
	encodedHash := hex.EncodeToString(hash[:])
	if _, ok := commonPasswordHashes[encodedHash]; ok {
		return "password is too common", nil
	}
	return "", nil
}
