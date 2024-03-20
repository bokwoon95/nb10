package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/term"
)

type ResetpasswordCmd struct {
	Notebrew     *nb10.Notebrew
	Stdout       io.Writer
	User         string
	PasswordHash string
	ResetLink    bool
}

func ResetpasswordCommand(nbrew *nb10.Notebrew, args ...string) (*ResetpasswordCmd, error) {
	var cmd ResetpasswordCmd
	cmd.Notebrew = nbrew
	var userProvided, passwordHashProvided bool
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("user", "", func(s string) error {
		userProvided = true
		cmd.User = strings.TrimSpace(s)
		return nil
	})
	flagset.Func("password-hash", "", func(s string) error {
		passwordHashProvided = true
		cmd.PasswordHash = strings.TrimSpace(s)
		return nil
	})
	flagset.BoolVar(&cmd.ResetLink, "reset-link", false, "")
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	if flagset.NArg() > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagset.Args(), " "))
	}
	if !userProvided || (!cmd.ResetLink && !passwordHashProvided) {
		fmt.Println("Press Ctrl+C to exit.")
		reader := bufio.NewReader(os.Stdin)
		if !userProvided {
			for {
				fmt.Print("Username or Email (leave blank for default user): ")
				text, err := reader.ReadString('\n')
				if err != nil {
					return nil, err
				}
				cmd.User = strings.TrimSpace(text)
				if !strings.HasPrefix(cmd.User, "@") && strings.Contains(cmd.User, "@") {
					email := cmd.User
					exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
						Dialect: cmd.Notebrew.Dialect,
						Format:  "SELECT 1 FROM users WHERE email = {email}",
						Values: []any{
							sq.StringParam("email", email),
						},
					})
					if err != nil {
						return nil, err
					}
					if !exists {
						fmt.Printf("no such user with email %q\n", email)
						continue
					}
				} else {
					username := strings.TrimPrefix(cmd.User, "@")
					exists, err := sq.FetchExists(context.Background(), cmd.Notebrew.DB, sq.Query{
						Dialect: cmd.Notebrew.Dialect,
						Format:  "SELECT 1 FROM users WHERE username = {username}",
						Values: []any{
							sq.StringParam("username", username),
						},
					})
					if err != nil {
						return nil, err
					}
					if !exists {
						fmt.Printf("no such user with username %q\n", username)
						continue
					}
				}
				break
			}
		}
		if !cmd.ResetLink && !passwordHashProvided {
			for {
				fmt.Print("Password (will be hidden from view, leave blank to generate password reset link): ")
				password, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Println()
				if err != nil {
					return nil, err
				}
				if len(password) == 0 {
					cmd.ResetLink = true
					return &cmd, nil
				}
				if utf8.RuneCount(password) < 8 {
					fmt.Println("Password must be at least 8 characters.")
					continue
				}
				commonPasswords, err := getCommonPasswords()
				if err != nil {
					return nil, err
				}
				if _, ok := commonPasswords[string(password)]; ok {
					fmt.Println("password is too common")
					continue
				}
				fmt.Print("Confirm password (will be hidden from view): ")
				confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Println()
				if err != nil {
					return nil, err
				}
				if subtle.ConstantTimeCompare(password, confirmPassword) != 1 {
					fmt.Fprintln(os.Stderr, "Passwords do not match.")
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
	}
	return &cmd, nil
}

func (cmd *ResetpasswordCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.ResetLink {
		var resetToken [8 + 16]byte
		binary.BigEndian.PutUint64(resetToken[:8], uint64(time.Now().Unix()))
		_, err := rand.Read(resetToken[8:])
		if err != nil {
			return err
		}
		checksum := blake2b.Sum256(resetToken[8:])
		var resetTokenHash [8 + blake2b.Size256]byte
		copy(resetTokenHash[:8], resetToken[:8])
		copy(resetTokenHash[8:], checksum[:])
		if !strings.HasPrefix(cmd.User, "@") && strings.Contains(cmd.User, "@") {
			email := cmd.User
			_, err = sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
				Dialect: cmd.Notebrew.Dialect,
				Format:  "UPDATE users SET password_hash = NULL, reset_token_hash = {resetTokenHash} WHERE email = {email}",
				Values: []any{
					sq.BytesParam("resetTokenHash", resetTokenHash[:]),
					sq.StringParam("email", email),
				},
			})
			if err != nil {
				return err
			}
		} else {
			_, err = sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
				Dialect: cmd.Notebrew.Dialect,
				Format:  "UPDATE users SET password_hash = NULL, reset_token_hash = {resetTokenHash} WHERE username = {username}",
				Values: []any{
					sq.BytesParam("resetTokenHash", resetTokenHash[:]),
					sq.StringParam("username", strings.TrimPrefix(cmd.User, "@")),
				},
			})
			if err != nil {
				return err
			}
		}
		fmt.Fprintln(os.Stderr, "generated password reset link:")
		scheme := "https://"
		if cmd.Notebrew.CMSDomain == "localhost" || strings.HasPrefix(cmd.Notebrew.CMSDomain, "localhost:") {
			scheme = "http://"
		}
		_, err = fmt.Fprintln(cmd.Stdout, scheme+cmd.Notebrew.CMSDomain+"/admin/resetpassword/?token="+url.QueryEscape(strings.TrimLeft(hex.EncodeToString(resetToken[:]), "0")))
		if err != nil {
			return err
		}
		return nil
	}
	tx, err := cmd.Notebrew.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if !strings.HasPrefix(cmd.User, "@") && strings.Contains(cmd.User, "@") {
		email := cmd.User
		_, err = sq.Exec(context.Background(), tx, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format: "DELETE FROM authentication WHERE EXISTS (" +
				"SELECT 1 FROM users WHERE users.user_id = authentication.user_id AND users.email = {email}" +
				")",
			Values: []any{
				sq.StringParam("email", email),
			},
		})
		if err != nil {
			return err
		}
		_, err = sq.Exec(context.Background(), tx, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format:  "UPDATE users SET password_hash = {passwordHash} WHERE email = {email}",
			Values: []any{
				sq.StringParam("passwordHash", cmd.PasswordHash),
				sq.StringParam("email", email),
			},
		})
		if err != nil {
			return err
		}
	} else {
		username := strings.TrimPrefix(cmd.User, "@")
		_, err = sq.Exec(context.Background(), tx, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format: "DELETE FROM authentication WHERE EXISTS (" +
				"SELECT 1 FROM users WHERE users.user_id = authentication.user_id AND users.username = {username}" +
				")",
			Values: []any{
				sq.StringParam("username", username),
			},
		})
		if err != nil {
			return err
		}
		_, err = sq.Exec(context.Background(), tx, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format:  "UPDATE users SET password_hash = {passwordHash} WHERE username = {username}",
			Values: []any{
				sq.StringParam("passwordHash", cmd.PasswordHash),
				sq.StringParam("username", username),
			},
		})
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "reset password")
	return nil
}
