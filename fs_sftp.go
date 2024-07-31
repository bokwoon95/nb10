package nb10

import (
	"context"
	"database/sql"
	"io/fs"
	"sync"
	"sync/atomic"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type FilesConfig struct {
	Provider       string            `json:"provider"`
	Dialect        string            `json:"dialect"`
	FilePath       string            `json:"filePath"`
	AuthMethod     string            `json:"authMethod"` // password | key (default is key)
	MaxConnections int               `json:"maxConnections"`
	User           string            `json:"user"`
	Password       string            `json:"password"`
	Host           string            `json:"host"`
	Port           string            `json:"port"`
	DBName         string            `json:"dbName"`
	Params         map[string]string `json:"params"`
}

type SFTPFSConfig struct {
	MaxConnections int
	NewSSHClient   func() (*ssh.Client, error)
}

type SFTPFS struct {
	ctx            context.Context
	newSSHClient   func() (*ssh.Client, error)
	sshClients     []*ssh.Client
	sshClientsOpen []atomic.Bool
	sshClientIndex atomic.Uint64
}

func (fsys *SFTPFS) newSFTPClient() (*sftp.Client, error) {
	return nil, nil
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

type SSHClientWrapper struct {
	Mutex     sync.Mutex
	SSHClient *ssh.Client
	Closed    bool
}

func NewSSHClientWrapper() {
}

func (sshClient *SSHClientWrapper) keepAlive(newSSHClient func() (*ssh.Client, error)) {
}

var _ = (*sql.DB)(nil).Query
