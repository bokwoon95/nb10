package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/nb10"
	"github.com/bokwoon95/nb10/sq"
	"golang.org/x/crypto/blake2b"
)

type CreateinviteCmd struct {
	Notebrew     *nb10.Notebrew
	Stdout       io.Writer
	SiteLimit    sql.NullInt64
	StorageLimit sql.NullInt64
	Count        sql.NullInt64
}

func CreateinviteCommand(nbrew *nb10.Notebrew, configDir string, args ...string) (*CreateinviteCmd, error) {
	if nbrew.DB == nil {
		return nil, fmt.Errorf("%s has not been configured: to fix, run `notebrew config database.dialect sqlite`", filepath.Join(configDir, "database.json"))
	}
	var cmd CreateinviteCmd
	cmd.Notebrew = nbrew
	flagset := flag.NewFlagSet("", flag.ContinueOnError)
	flagset.Func("site-limit", "", func(s string) error {
		siteLimit, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not a valid count", s)
		}
		cmd.SiteLimit = sql.NullInt64{Int64: siteLimit, Valid: true}
		return nil
	})
	flagset.Func("storage-limit", "", func(s string) error {
		storageLimit, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not a valid count", s)
		}
		cmd.StorageLimit = sql.NullInt64{Int64: storageLimit, Valid: true}
		return nil
	})
	flagset.Func("count", "", func(s string) error {
		count, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not a valid count", s)
		}
		cmd.Count = sql.NullInt64{Int64: count, Valid: true}
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
	return &cmd, nil
}

func (cmd *CreateinviteCmd) Run() error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	count := 1
	if cmd.Count.Valid {
		count = int(cmd.Count.Int64)
	}
	scheme := "https://"
	if cmd.Notebrew.CMSDomain == "localhost" || strings.HasPrefix(cmd.Notebrew.CMSDomain, "localhost:") {
		scheme = "http://"
	}
	for i := 0; i < count; i++ {
		var inviteToken [8 + 16]byte
		binary.BigEndian.PutUint64(inviteToken[:8], uint64(time.Now().Unix()))
		_, err := rand.Read(inviteToken[8:])
		if err != nil {
			return err
		}
		checksum := blake2b.Sum256(inviteToken[8:])
		var inviteTokenHash [8 + blake2b.Size256]byte
		copy(inviteTokenHash[:8], inviteToken[:8])
		copy(inviteTokenHash[8:], checksum[:])
		_, err = sq.Exec(context.Background(), cmd.Notebrew.DB, sq.Query{
			Dialect: cmd.Notebrew.Dialect,
			Format: "INSERT INTO invite (invite_token_hash, site_limit, storage_limit)" +
				" VALUES ({inviteTokenHash}, {siteLimit}, {storageLimit})",
			Values: []any{
				sq.BytesParam("inviteTokenHash", inviteTokenHash[:]),
				sq.Param("siteLimit", cmd.SiteLimit),
				sq.Param("storageLimit", cmd.StorageLimit),
			},
		})
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.Stdout, scheme+cmd.Notebrew.CMSDomain+"/admin/signup/?token="+strings.TrimLeft(hex.EncodeToString(inviteToken[:]), "0"))
	}
	return nil
}
