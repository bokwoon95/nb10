package nb10

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sync/errgroup"
)

type DirFSConfig struct {
	// RootDir is the root directory of the DirFS.
	RootDir string

	// TempDir is the temp directory of the DirFS.
	TempDir string
}

// DirFS represents a filesystem rooted on a directory.
type DirFS struct {
	// Context provides the context of all operations called on the DirFS.
	Context context.Context

	// RootDir is the root directory of the DirFS. Has to be an absolute
	// path!!
	RootDir string

	// TempDir is the temp directory of the DirFS. Files are first written to
	// the TempDir before being swapped into the rootDir via an atomic rename
	// (windows is the exception I've found the renames there to be BUGGY AF!
	// *insert github issue where rename on windows keep failing intermittently
	// with an annoying permission error*)
	TempDir string
}

func NewDirFS(config DirFSConfig) (*DirFS, error) {
	rootDir, err := filepath.Abs(filepath.FromSlash(config.RootDir))
	if err != nil {
		return nil, err
	}
	tempDir, err := filepath.Abs(filepath.FromSlash(config.TempDir))
	if err != nil {
		return nil, err
	}
	dirFS := &DirFS{
		Context: context.Background(),
		RootDir: rootDir,
		TempDir: tempDir,
	}
	return dirFS, nil
}

func (fsys *DirFS) WithContext(ctx context.Context) FS {
	return &DirFS{
		Context: ctx,
		RootDir: fsys.RootDir,
		TempDir: fsys.TempDir,
	}
}

func (fsys *DirFS) Open(name string) (fs.File, error) {
	err := fsys.Context.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	file, err := os.Open(filepath.Join(fsys.RootDir, name))
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (fsys *DirFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.Context.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	fileInfo, err := os.Stat(filepath.Join(fsys.RootDir, name))
	if err != nil {
		return nil, err
	}
	return fileInfo, nil
}

func (fsys *DirFS) OpenWriter(name string, _ fs.FileMode) (io.WriteCloser, error) {
	err := fsys.Context.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	if runtime.GOOS == "windows" {
		file, err := os.OpenFile(filepath.Join(fsys.RootDir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return nil, err
		}
		return file, nil
	}
	file := &DirFileWriter{
		ctx:     fsys.Context,
		rootDir: fsys.RootDir,
		tempDir: fsys.TempDir,
		name:    filepath.FromSlash(name),
	}
	if file.tempDir == "" {
		file.tempDir = os.TempDir()
	}
	fmt.Printf("openwriter %s\n", name)
	file.tempFile, err = os.CreateTemp(file.tempDir, "notebrew-temp-*"+path.Ext(name))
	if err != nil {
		return nil, err
	}
	fileInfo, err := file.tempFile.Stat()
	if err != nil {
		return nil, err
	}
	file.tempName = fileInfo.Name()
	return file, nil
}

// DirFileWriter represents a writable file on a DirFS.
type DirFileWriter struct {
	// ctx provides the context of all operations called on the file.
	ctx context.Context

	// rootDir is the root directory that houses the destination file.
	rootDir string

	// name is the name of the destination file relative to rootDir.
	name string

	// tempFile is temporary file we are writing to first before we do an
	// atomic rename into the destination file. This ensures that parallel
	// writers do not corrupt the destination file, writes are always all or
	// nothing and the last writer wins.
	tempFile *os.File

	// tempDir is the temp directory that houses the temporary file.
	tempDir string

	// tempName is the name of the temporary file relative to tempDir. It is
	// randomly generated by os.CreateTemp.
	tempName string

	// writeFailed records if any writes to the tempFile failed.
	writeFailed bool
}

func (file *DirFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
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

func (file *DirFileWriter) Write(p []byte) (n int, err error) {
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

func (file *DirFileWriter) Close() error {
	tempFilePath := filepath.Join(file.tempDir, file.tempName)
	destFilePath := filepath.Join(file.rootDir, file.name)
	defer os.Remove(tempFilePath)
	err := file.tempFile.Close()
	if err != nil {
		return err
	}
	if file.writeFailed {
		return nil
	}
	err = os.Rename(tempFilePath, destFilePath)
	if err != nil {
		return err
	}
	return nil
}

func (fsys *DirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	err := fsys.Context.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.ReadDir(filepath.Join(fsys.RootDir, name))
}

func (fsys *DirFS) Mkdir(name string, _ fs.FileMode) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.Mkdir(filepath.Join(fsys.RootDir, name), 0755)
}

func (fsys *DirFS) MkdirAll(name string, _ fs.FileMode) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdirall", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.MkdirAll(filepath.Join(fsys.RootDir, name), 0755)
}

func (fsys *DirFS) Remove(name string) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.Remove(filepath.Join(fsys.RootDir, name))
}

func (fsys *DirFS) RemoveAll(name string) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.RemoveAll(filepath.Join(fsys.RootDir, name))
}

func (fsys *DirFS) Rename(oldName, newName string) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(oldName) || strings.Contains(oldName, "\\") {
		return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newName) || strings.Contains(newName, "\\") {
		return &fs.PathError{Op: "rename", Path: newName, Err: fs.ErrInvalid}
	}
	oldName = filepath.FromSlash(oldName)
	newName = filepath.FromSlash(newName)
	_, err = os.Stat(filepath.Join(fsys.RootDir, newName))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else {
		return &fs.PathError{Op: "rename", Path: newName, Err: fs.ErrExist}
	}
	err = os.Rename(filepath.Join(fsys.RootDir, oldName), filepath.Join(fsys.RootDir, newName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
		}
		return nil
	}
	return nil
}

func (fsys *DirFS) Copy(srcName, destName string) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(srcName) || strings.Contains(srcName, "\\") {
		return &fs.PathError{Op: "copy", Path: srcName, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(destName) || strings.Contains(destName, "\\") {
		return &fs.PathError{Op: "copy", Path: destName, Err: fs.ErrInvalid}
	}
	srcName = filepath.FromSlash(srcName)
	destName = filepath.FromSlash(destName)
	_, err = os.Stat(filepath.Join(fsys.RootDir, destName))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else {
		return &fs.PathError{Op: "copy", Path: destName, Err: fs.ErrExist}
	}
	srcFileInfo, err := os.Stat(filepath.Join(fsys.RootDir, srcName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &fs.PathError{Op: "copy", Path: srcName, Err: fs.ErrNotExist}
		}
		return err
	}
	if !srcFileInfo.IsDir() {
		srcFile, err := fsys.WithContext(fsys.Context).Open(srcName)
		if err != nil {
			return err
		}
		defer srcFile.Close()
		destFile, err := fsys.WithContext(fsys.Context).OpenWriter(destName, 0644)
		if err != nil {
			return err
		}
		defer destFile.Close()
		_, err = io.Copy(destFile, srcFile)
		if err != nil {
			return err
		}
		err = destFile.Close()
		if err != nil {
			return err
		}
		return nil
	}
	group, groupctx := errgroup.WithContext(fsys.Context)
	err = fs.WalkDir(fsys.WithContext(groupctx), srcName, func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relativePath := strings.TrimPrefix(strings.TrimPrefix(filePath, srcName), string(os.PathSeparator))
		if dirEntry.IsDir() {
			err := fsys.WithContext(groupctx).MkdirAll(path.Join(destName, relativePath), 0755)
			if err != nil {
				return err
			}
			return nil
		}
		group.Go(func() error {
			srcFile, err := fsys.WithContext(groupctx).Open(filePath)
			if err != nil {
				return err
			}
			defer srcFile.Close()
			destFile, err := fsys.WithContext(groupctx).OpenWriter(path.Join(destName, relativePath), 0644)
			if err != nil {
				return err
			}
			defer destFile.Close()
			_, err = io.Copy(destFile, srcFile)
			if err != nil {
				return err
			}
			err = destFile.Close()
			if err != nil {
				return err
			}
			return nil
		})
		return nil
	})
	if err != nil {
		return err
	}
	err = group.Wait()
	if err != nil {
		return err
	}
	return nil
}
