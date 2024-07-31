package nb10

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
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
	NewSSHClient   func() (*ssh.Client, error)
	RootDir        string
	TempDir        string
	MaxConnections int
}

type SFTPFS struct {
	Clients      []*SFTPClient
	NewSSHClient func() (*ssh.Client, error)
	RootDir      string
	TempDir      string
	index        atomic.Uint64
	ctx          context.Context
}

func NewSFTPFS(config SFTPFSConfig) (*SFTPFS, error) {
	rootDir := filepath.ToSlash(config.RootDir)
	tempDir := filepath.ToSlash(config.TempDir)
	maxConnections := config.MaxConnections
	if maxConnections < 1 {
		maxConnections = 1
	}
	sftpFS := &SFTPFS{
		Clients:      make([]*SFTPClient, 0, maxConnections),
		NewSSHClient: config.NewSSHClient,
		RootDir:      rootDir,
		TempDir:      tempDir,
		ctx:          context.Background(),
	}
	for i := 0; i < maxConnections; i++ {
		sftpFS.Clients = append(sftpFS.Clients, &SFTPClient{})
	}
	_, err := sftpFS.Clients[0].Get(sftpFS.NewSSHClient)
	if err != nil {
		return nil, err
	}
	return sftpFS, nil
}

func (fsys *SFTPFS) WithContext(ctx context.Context) FS {
	return nil // TODO
}

func (fsys *SFTPFS) WithValues(ctx context.Context) FS {
	return nil // TODO
}

func (fsys *SFTPFS) Open(name string) (fs.File, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return nil, err
	}
	file, err := sftpClient.Open(path.Join(fsys.RootDir, name))
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (fsys *SFTPFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return nil, err
	}
	fileInfo, err := sftpClient.Stat(path.Join(fsys.RootDir, name))
	if err != nil {
		return nil, err
	}
	return fileInfo, nil
}

func (fsys *SFTPFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return nil, err
	}
	_, err = sftpClient.Stat(path.Join(fsys.RootDir, path.Dir(name)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	file := &SFTPFileWriter{
		ctx:        fsys.ctx,
		sftpClient: sftpClient,
		rootDir:    fsys.RootDir,
		tempDir:    fsys.TempDir,
		name:       name,
	}
	if file.tempDir == "" {
		file.tempDir = "/tmp"
	}
	file.tempName = NewID().String() + path.Ext(name)
	file.tempFile, err = sftpClient.OpenFile(path.Join(fsys.RootDir, file.tempName), os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// SFTPFileWriter represents a writable file on an SFTPFS.
type SFTPFileWriter struct {
	// ctx provides the context of all operations called on the file.
	ctx context.Context

	sftpClient *sftp.Client

	// rootDir is the root directory that houses the destination file.
	rootDir string

	// name is the name of the destination file relative to rootDir.
	name string

	// tempFile is temporary file we are writing to first before we do an
	// atomic rename into the destination file. This ensures that parallel
	// writers do not corrupt the destination file, writes are always all or
	// nothing and the last writer wins.
	tempFile *sftp.File

	// tempDir is the temp directory that houses the temporary file.
	tempDir string

	// tempName is the name of the temporary file relative to tempDir.
	tempName string

	// writeFailed records if any writes to the tempFile failed.
	writeFailed bool
}

func (file *SFTPFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	n, err = file.tempFile.ReadFrom(r)
	if err != nil {
		file.writeFailed = true
		return n, err
	}
	return n, nil
}

func (file *SFTPFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	n, err = file.tempFile.Write(p)
	if err != nil {
		file.writeFailed = true
		return n, err
	}
	return n, nil
}

func (file *SFTPFileWriter) Close() error {
	tempFilePath := path.Join(file.tempDir, file.tempName)
	destFilePath := path.Join(file.rootDir, file.name)
	defer file.sftpClient.Remove(tempFilePath)
	err := file.tempFile.Close()
	if err != nil {
		return err
	}
	if file.writeFailed {
		return nil
	}
	if _, ok := file.sftpClient.HasExtension("posix-rename@openssh.com"); ok {
		err := file.sftpClient.PosixRename(tempFilePath, destFilePath)
		if err != nil {
			return err
		}
	} else {
		err := file.sftpClient.Rename(tempFilePath, destFilePath)
		if err != nil {
			return err
		}
	}
	return nil
}

func (fsys *SFTPFS) ReadDir(name string) ([]fs.DirEntry, error) {
	err := fsys.ctx.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return nil, err
	}
	fileInfos, err := sftpClient.ReadDir(name)
	if err != nil {
		return nil, err
	}
	dirEntries := make([]fs.DirEntry, len(fileInfos))
	for i := range fileInfos {
		dirEntries[i] = fs.FileInfoToDirEntry(fileInfos[i])
	}
	return dirEntries, nil
}

func (fsys *SFTPFS) Mkdir(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return err
	}
	return sftpClient.Mkdir(path.Join(fsys.RootDir, name))
}

func (fsys *SFTPFS) MkdirAll(name string, _ fs.FileMode) error {
	err := fsys.ctx.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	sftpClient, err := fsys.Clients[int(fsys.index.Add(1))%len(fsys.Clients)].Get(fsys.NewSSHClient)
	if err != nil {
		return err
	}
	return sftpClient.MkdirAll(path.Join(fsys.RootDir, name))
}

func (fsys *SFTPFS) Close() error {
	var closeErr error
	for _, client := range fsys.Clients {
		err := client.sftpClient.Close()
		if err != nil {
			if closeErr == nil {
				closeErr = err
			}
		}
	}
	return closeErr
}

type SFTPClient struct {
	mutex        sync.RWMutex
	disconnected bool
	sftpClient   *sftp.Client
}

func (conn *SFTPClient) Get(newSSHClient func() (*ssh.Client, error)) (*sftp.Client, error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if !conn.disconnected && conn.sftpClient != nil {
		return conn.sftpClient, nil
	}
	sshClient, err := newSSHClient()
	if err != nil {
		return nil, err
	}
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, err
	}
	conn.sftpClient = sftpClient
	conn.disconnected = false
	go func() {
		sshClient.Wait()
		conn.mutex.Lock()
		conn.disconnected = true
		conn.mutex.Unlock()
	}()
	return conn.sftpClient, nil
}
