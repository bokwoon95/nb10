package nb10

import (
	"context"
	"database/sql"
	"io/fs"
	"sync/atomic"

	"github.com/pkg/sftp"
)

type DatabaseConfig struct {
	Provider   string            `json:"provider"`
	Dialect    string            `json:"dialect"`
	FilePath   string            `json:"filePath"`
	AuthMethod string            `json:"authMethod"`
	User       string            `json:"user"`
	Password   string            `json:"password"`
	Host       string            `json:"host"`
	Port       string            `json:"port"`
	DBName     string            `json:"dbName"`
	Params     map[string]string `json:"params"`
}

type SFTPFSConfig struct {
	Auth     string // password | key (default is key)
	User     string
	Password string
}

type SFTPFS struct {
	ctx context.Context
}

func (fsys *SFTPFS) WithContext(ctx context.Context) FS {
	return nil // TODO
}

func (fsys *SFTPFS) WithValues(ctx context.Context) FS {
	return nil // TODO
}

func (fsys *SFTPFS) Open(name string) (fs.File, error) {
	return nil, nil
}

type SFTPClient struct {
	*sftp.Client
	closed atomic.Bool
}

type SFTPClientPool struct {
}

func (sftpClientPool *SFTPClientPool) GetClient() {
}

var _ = (*sql.DB)(nil).Query
