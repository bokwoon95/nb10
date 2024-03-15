package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/crypto/blake2b"
)

type DeleteinviteCmd struct {
	Notebrew *nb10.Notebrew
	Before   sql.NullTime
	After    sql.NullTime
}

func DeleteinviteCommand(nbrew *nb10.Notebrew, args ...string) (*DeleteinviteCmd, error) {
	var cmd DeleteinviteCmd
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("before", "", func(s string) error {
		before, err := parseTime(s)
		if err != nil {
			return err
		}
		cmd.Before = before
		return nil
	})
	flagset.Func("after", "", func(s string) error {
		after, err := parseTime(s)
		if err != nil {
			return err
		}
		cmd.After = after
		return nil
	})
	err := flagset.Parse(args)
	if err != nil {
		return nil, err
	}
	flagArgs := flagset.Args()
	if len(flagArgs) > 0 {
		flagset.Usage()
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flagArgs, " "))
	}
	if !cmd.Before.Valid && !cmd.After.Valid {
		fmt.Println("Press Ctrl+C to exit.")
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Delete all invites? (y/n): ")
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			text = strings.TrimSpace(text)
			if text == "y" {
				break
			}
			if text == "n" {
				fmt.Println("cancelled")
				return nil, flag.ErrHelp
			}
		}
	}
	return &cmd, nil
}

func (cmd *DeleteinviteCmd) Run() error {
	var exprs []string
	var args []any
	if cmd.Before.Valid {
		inviteTokenHash := make([]byte, 8+blake2b.Size256)
		binary.BigEndian.PutUint64(inviteTokenHash[:8], uint64(cmd.Before.Time.Unix()))
		exprs = append(exprs, "invite_token_hash < {}")
		args = append(args, inviteTokenHash)
	}
	if cmd.After.Valid {
		inviteTokenHash := make([]byte, 8+blake2b.Size256)
		binary.BigEndian.PutUint64(inviteTokenHash[:8], uint64(cmd.Before.Time.Unix()))
		exprs = append(exprs, "invite_token_hash > {}")
		args = append(args, inviteTokenHash)
	}
	condition := sq.Expr("1 = 1")
	if len(exprs) > 0 {
		condition = sq.Expr(strings.Join(exprs, " AND "), args...)
	}
	result, err := sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
		Dialect: cmd.Notebrew.Dialect,
		Format:  "DELETE FROM invite WHERE {condition}",
		Values: []any{
			sq.Param("condition", condition),
		},
	})
	if err != nil {
		return err
	}
	if result.RowsAffected == 1 {
		fmt.Println("1 invite deleted")
	} else {
		fmt.Println(strconv.FormatInt(result.RowsAffected, 10) + " invites deleted")
	}
	return nil
}

func parseTime(s string) (sql.NullTime, error) {
	if s == "" {
		return sql.NullTime{}, nil
	}
	if s == "now" {
		return sql.NullTime{Time: time.Now(), Valid: true}, nil
	}
	for _, format := range []string{
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999-07",
		"2006-01-02T15:04:05.999999999-07",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04",
		"2006-01-02T15:04",
		"2006-01-02",
	} {
		if t, err := time.ParseInLocation(format, s, time.UTC); err == nil {
			return sql.NullTime{Time: t, Valid: true}, nil
		}
	}
	return sql.NullTime{}, fmt.Errorf("not a valid time string")
}
