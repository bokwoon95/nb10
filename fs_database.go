package nb10

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/bokwoon95/nb10/sq"
)

var wildcardReplacer = strings.NewReplacer("%", "\\%", "_", "\\_")

var gzipReaderPool = sync.Pool{}

var gzipWriterPool = sync.Pool{
	New: func() any {
		// Use compression level 4 for best balance between space and
		// performance.
		// https://blog.klauspost.com/gzip-performance-for-go-webservers/
		gzipWriter, _ := gzip.NewWriterLevel(nil, 4)
		return gzipWriter
	},
}

type DatabaseFSConfig struct {
	DB            *sql.DB
	Dialect       string
	ErrorCode     func(error) string
	ObjectStorage ObjectStorage
	Logger        *slog.Logger
}

type DatabaseFS struct {
	Context       context.Context
	DB            *sql.DB
	Dialect       string
	ErrorCode     func(error) string
	ObjectStorage ObjectStorage
	Logger        *slog.Logger
}

func NewDatabaseFS(config DatabaseFSConfig) (*DatabaseFS, error) {
	databaseFS := &DatabaseFS{
		Context:       context.Background(),
		DB:            config.DB,
		Dialect:       config.Dialect,
		ErrorCode:     config.ErrorCode,
		ObjectStorage: config.ObjectStorage,
		Logger:        config.Logger,
	}
	return databaseFS, nil
}

func (fsys *DatabaseFS) WithContext(ctx context.Context) FS {
	return &DatabaseFS{
		Context:       ctx,
		DB:            fsys.DB,
		Dialect:       fsys.Dialect,
		ErrorCode:     fsys.ErrorCode,
		ObjectStorage: fsys.ObjectStorage,
		Logger:        fsys.Logger,
	}
}

type DatabaseFileInfo struct {
	FileID       ID
	FilePath     string
	isDir        bool
	size         int64
	modTime      time.Time
	CreationTime time.Time
}

type DatabaseFile struct {
	ctx               context.Context
	fileType          FileType
	isFulltextIndexed bool
	objectStorage     ObjectStorage
	info              *DatabaseFileInfo
	buf               *bytes.Buffer
	gzipReader        *gzip.Reader
	readCloser        io.ReadCloser
}

func (fsys *DatabaseFS) Open(name string) (fs.File, error) {
	err := fsys.Context.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		file := &DatabaseFile{
			ctx:           fsys.Context,
			objectStorage: fsys.ObjectStorage,
			info:          &DatabaseFileInfo{FilePath: ".", isDir: true},
		}
		return file, nil
	}
	var fileType FileType
	if ext := path.Ext(name); ext != "" {
		fileType = fileTypes[ext]
	}
	file, err := sq.FetchOne(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) *DatabaseFile {
		file := &DatabaseFile{
			ctx:           fsys.Context,
			fileType:      fileType,
			objectStorage: fsys.ObjectStorage,
			info:          &DatabaseFileInfo{},
		}
		file.info.FileID = row.UUID("file_id")
		file.info.FilePath = row.String("file_path")
		file.info.isDir = row.Bool("is_dir")
		file.info.size = row.Int64("size")
		file.info.modTime = row.Time("mod_time")
		file.info.CreationTime = row.Time("creation_time")
		if !fileType.IsObject {
			file.buf = bytes.NewBuffer(row.Bytes(bufPool.Get().(*bytes.Buffer).Bytes(), "COALESCE(text, data)"))
		}
		return file
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	file.isFulltextIndexed = isFulltextIndexed(file.info.FilePath)
	if fileType.IsObject {
		file.readCloser, err = file.objectStorage.Get(file.ctx, file.info.FileID.String()+path.Ext(file.info.FilePath))
		if err != nil {
			return nil, err
		}
		if file, ok := file.readCloser.(fs.File); ok {
			return file, nil
		}
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			// Do NOT pass file.buf directly to gzip.Reader or it will do an
			// unwanted read from the buffer! We want to keep file.buf unread
			// in case someone wants to reach directly into it and pull out the
			// raw gzipped bytes.
			r := bytes.NewReader(file.buf.Bytes())
			file.gzipReader, _ = gzipReaderPool.Get().(*gzip.Reader)
			if file.gzipReader != nil {
				err = file.gzipReader.Reset(r)
				if err != nil {
					return nil, err
				}
			} else {
				file.gzipReader, err = gzip.NewReader(r)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return file, nil
}

func (fsys *DatabaseFS) Stat(name string) (fs.FileInfo, error) {
	err := fsys.Context.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &DatabaseFileInfo{FilePath: ".", isDir: true}, nil
	}
	fileInfo, err := sq.FetchOne(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) *DatabaseFileInfo {
		return &DatabaseFileInfo{
			FileID:       row.UUID("file_id"),
			FilePath:     row.String("file_path"),
			isDir:        row.Bool("is_dir"),
			size:         row.Int64("size"),
			modTime:      row.Time("mod_time"),
			CreationTime: row.Time("creation_time"),
		}
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	return fileInfo, nil
}

func (fileInfo *DatabaseFileInfo) Name() string { return path.Base(fileInfo.FilePath) }

func (fileInfo *DatabaseFileInfo) Size() int64 { return fileInfo.size }

func (fileInfo *DatabaseFileInfo) ModTime() time.Time { return fileInfo.modTime }

func (fileInfo *DatabaseFileInfo) IsDir() bool { return fileInfo.isDir }

func (fileInfo *DatabaseFileInfo) Sys() any { return nil }

func (fileInfo *DatabaseFileInfo) Type() fs.FileMode { return fileInfo.Mode().Type() }

func (fileInfo *DatabaseFileInfo) Info() (fs.FileInfo, error) { return fileInfo, nil }

func (fileInfo *DatabaseFileInfo) Mode() fs.FileMode {
	if fileInfo.isDir {
		return fs.ModeDir
	}
	return 0
}

func (file *DatabaseFile) Stat() (fs.FileInfo, error) {
	return file.info, nil
}

func (file *DatabaseFile) Read(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		return 0, err
	}
	if file.info.isDir {
		return 0, &fs.PathError{Op: "read", Path: file.info.FilePath, Err: syscall.EISDIR}
	}
	if file.fileType.IsObject {
		return file.readCloser.Read(p)
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			return file.gzipReader.Read(p)
		} else {
			return file.buf.Read(p)
		}
	}
}

type emptyReader struct{}

var empty = (*emptyReader)(nil)

func (empty *emptyReader) Read(p []byte) (n int, err error) { return 0, io.EOF }

func (file *DatabaseFile) Close() error {
	if file.info.isDir {
		return nil
	}
	if file.fileType.IsObject {
		if file.readCloser == nil {
			return fs.ErrClosed
		}
		err := file.readCloser.Close()
		if err != nil {
			return err
		}
		file.readCloser = nil
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			if file.gzipReader == nil {
				return fs.ErrClosed
			}
			file.gzipReader.Reset(empty)
			gzipReaderPool.Put(file.gzipReader)
			file.gzipReader = nil
			if file.buf.Cap() <= maxPoolableBufferCapacity {
				file.buf.Reset()
				bufPool.Put(file.buf)
			}
			file.buf = nil
		} else {
			if file.buf == nil {
				return fs.ErrClosed
			}
			if file.buf.Cap() <= maxPoolableBufferCapacity {
				file.buf.Reset()
				bufPool.Put(file.buf)
			}
			file.buf = nil
		}
	}
	return nil
}

type DatabaseFileWriter struct {
	ctx                 context.Context
	fileType            FileType
	isFulltextIndexed   bool
	db                  *sql.DB
	dialect             string
	objectStorage       ObjectStorage
	exists              bool
	fileID              ID
	parentID            ID
	filePath            string
	size                int64
	buf                 *bytes.Buffer
	gzipWriter          *gzip.Writer
	modTime             time.Time
	objectStorageWriter *io.PipeWriter
	objectStorageResult chan error
	writeFailed         bool
	logger              *slog.Logger
}

func (fsys *DatabaseFS) OpenWriter(name string, _ fs.FileMode) (io.WriteCloser, error) {
	err := fsys.Context.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
	}
	var fileType FileType
	if ext := path.Ext(name); ext != "" {
		fileType = fileTypes[ext]
	}
	file := &DatabaseFileWriter{
		ctx:               fsys.Context,
		fileType:          fileType,
		isFulltextIndexed: isFulltextIndexed(name),
		db:                fsys.DB,
		dialect:           fsys.Dialect,
		objectStorage:     fsys.ObjectStorage,
		filePath:          name,
		modTime:           time.Now().UTC(),
		logger:            fsys.Logger,
	}
	// If parentDir is the root directory, just fetch the file information.
	// Otherwise fetch both the parent and file information.
	parentDir := path.Dir(file.filePath)
	if parentDir == "." {
		result, err := sq.FetchOne(fsys.Context, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {filePath}",
			Values: []any{
				sq.StringParam("filePath", file.filePath),
			},
		}, func(row *sq.Row) (result struct {
			fileID ID
			isDir  bool
		}) {
			result.fileID = row.UUID("file_id")
			result.isDir = row.Bool("is_dir")
			return result
		})
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
		} else {
			if result.isDir {
				return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
			}
			file.fileID = result.fileID
		}
	} else {
		results, err := sq.FetchAll(fsys.Context, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path IN ({parentDir}, {filePath})",
			Values: []any{
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", file.filePath),
			},
		}, func(row *sq.Row) (result struct {
			fileID   ID
			filePath string
			isDir    bool
		}) {
			result.fileID = row.UUID("file_id")
			result.filePath = row.String("file_path")
			result.isDir = row.Bool("is_dir")
			return result
		})
		if err != nil {
			return nil, err
		}
		for _, result := range results {
			switch result.filePath {
			case name:
				if result.isDir {
					return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
				}
				file.fileID = result.fileID
			case parentDir:
				if !result.isDir {
					return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.ENOTDIR}
				}
				file.parentID = result.fileID
			}
		}
		if file.parentID.IsZero() {
			return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrNotExist}
		}
	}
	if file.fileID.IsZero() {
		file.fileID = NewID()
	} else {
		file.exists = true
	}
	if fileType.IsObject {
		pipeReader, pipeWriter := io.Pipe()
		file.objectStorageWriter = pipeWriter
		file.objectStorageResult = make(chan error, 1)
		go func() {
			file.objectStorageResult <- fsys.ObjectStorage.Put(file.ctx, file.fileID.String()+path.Ext(file.filePath), pipeReader)
			close(file.objectStorageResult)
		}()
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			file.buf = bufPool.Get().(*bytes.Buffer)
			file.gzipWriter = gzipWriterPool.Get().(*gzip.Writer)
			file.gzipWriter.Reset(file.buf)
		} else {
			file.buf = bufPool.Get().(*bytes.Buffer)
		}
	}
	return file, nil
}

func (file *DatabaseFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	if file.fileType.IsObject {
		n, err = file.objectStorageWriter.Write(p)
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			n, err = file.gzipWriter.Write(p)
		} else {
			n, err = file.buf.Write(p)
		}
	}
	file.size += int64(n)
	if err != nil {
		file.writeFailed = true
	}
	return n, err
}

func (file *DatabaseFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	if file.fileType.IsObject {
		n, err = io.Copy(file.objectStorageWriter, r)
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			n, err = io.Copy(file.gzipWriter, r)
		} else {
			n, err = file.buf.ReadFrom(r)
		}
	}
	file.size += int64(n)
	if err != nil {
		file.writeFailed = true
	}
	return n, err
}

func (file *DatabaseFileWriter) Close() error {
	if file.fileType.IsObject {
		if file.objectStorageWriter == nil {
			return fs.ErrClosed
		}
		file.objectStorageWriter.Close()
		file.objectStorageWriter = nil
		err := <-file.objectStorageResult
		if err != nil {
			return err
		}
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			if file.gzipWriter == nil {
				return fs.ErrClosed
			}
			err := file.gzipWriter.Close()
			if err != nil {
				return err
			}
			defer func() {
				file.gzipWriter.Reset(io.Discard)
				gzipWriterPool.Put(file.gzipWriter)
				file.gzipWriter = nil
				if file.buf.Cap() <= maxPoolableBufferCapacity {
					file.buf.Reset()
					bufPool.Put(file.buf)
				}
				file.buf = nil
			}()
		} else {
			if file.buf == nil {
				return fs.ErrClosed
			}
			defer func() {
				if file.buf.Cap() <= maxPoolableBufferCapacity {
					file.buf.Reset()
					bufPool.Put(file.buf)
				}
				file.buf = nil
			}()
		}
	}
	if file.writeFailed {
		if file.fileType.IsObject {
			err := file.objectStorage.Delete(file.ctx, file.fileID.String()+path.Ext(file.filePath))
			if err != nil {
				file.logger.Error(err.Error())
			}
		}
		return nil
	}

	// If file exists, just have to update the file entry in the database.
	if file.exists {
		if file.fileType.IsObject {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format:  "UPDATE files SET text = NULL, data = NULL, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
				Values: []any{
					sq.Int64Param("size", file.size),
					sq.TimeParam("modTime", file.modTime),
					sq.UUIDParam("fileID", file.fileID),
				},
			})
			if err != nil {
				return err
			}
		} else {
			if file.fileType.IsGzippable && !file.isFulltextIndexed {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = NULL, data = {data}, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("data", file.buf.Bytes()),
						sq.Int64Param("size", file.size),
						sq.TimeParam("modTime", file.modTime),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return err
				}
			} else {
				_, err := sq.Exec(file.ctx, file.db, sq.Query{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = {text}, data = NULL, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("text", file.buf.Bytes()),
						sq.Int64Param("size", file.size),
						sq.TimeParam("modTime", file.modTime),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return err
				}
			}
		}
		return nil
	}

	// If we reach here it means file doesn't exist. Insert a new file entry
	// into the database.
	if file.fileType.IsObject {
		_, err := sq.Exec(file.ctx, file.db, sq.Query{
			Dialect: file.dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, size, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {parentID}, {filePath}, {size}, {modTime}, {modTime}, FALSE)",
			Values: []any{
				sq.UUIDParam("fileID", file.fileID),
				sq.UUIDParam("parentID", file.parentID),
				sq.StringParam("filePath", file.filePath),
				sq.Int64Param("size", file.size),
				sq.TimeParam("modTime", file.modTime),
			},
		})
		if err != nil {
			go func() {
				err := file.objectStorage.Delete(context.Background(), file.fileID.String()+path.Ext(file.filePath))
				if err != nil {
					file.logger.Error(err.Error())
				}
			}()
			return err
		}
	} else {
		if file.fileType.IsGzippable && !file.isFulltextIndexed {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, size, data, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {size}, {data}, {modTime}, {modTime}, FALSE)",
				Values: []any{
					sq.UUIDParam("fileID", file.fileID),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.Int64Param("size", file.size),
					sq.BytesParam("data", file.buf.Bytes()),
					sq.TimeParam("modTime", file.modTime),
				},
			})
			if err != nil {
				return err
			}
		} else {
			_, err := sq.Exec(file.ctx, file.db, sq.Query{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, size, text, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {size}, {text}, {modTime}, {modTime}, FALSE)",
				Values: []any{
					sq.UUIDParam("fileID", file.fileID),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.Int64Param("size", file.size),
					sq.BytesParam("text", file.buf.Bytes()),
					sq.TimeParam("modTime", file.modTime),
				},
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (fsys *DatabaseFS) ReadDir(name string) ([]fs.DirEntry, error) {
	err := fsys.Context.Err()
	if err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	// TODO: return syscall.ENOTDIR if name is not a dir? Or follow stdlib and
	// return fs.ErrNotExist?
	var condition sq.Expression
	if name == "." {
		condition = sq.Expr("parent_id IS NULL")
	} else {
		condition = sq.Expr("parent_id = (SELECT file_id FROM files WHERE file_path = {})", name)
	}
	dirEntries, err := sq.FetchAll(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE {condition}",
		Values: []any{
			sq.Param("condition", condition),
		},
	}, func(row *sq.Row) fs.DirEntry {
		file := &DatabaseFileInfo{}
		file.FileID = row.UUID("file_id")
		file.FilePath = row.String("file_path")
		file.isDir = row.Bool("is_dir")
		file.size = row.Int64("size")
		file.modTime = row.Time("mod_time")
		file.CreationTime = row.Time("creation_time")
		return file
	})
	if err != nil {
		return nil, err
	}
	return dirEntries, nil
}

func (fsys *DatabaseFS) Mkdir(name string, _ fs.FileMode) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil
	}
	modTime := time.Now().UTC()
	parentDir := path.Dir(name)
	if parentDir == "." {
		_, err := sq.Exec(fsys.Context, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, {modTime}, TRUE)",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", name),
				sq.TimeParam("modTime", modTime),
			},
		})
		if err != nil {
			if fsys.ErrorCode == nil {
				return err
			}
			errcode := fsys.ErrorCode(err)
			if IsKeyViolation(fsys.Dialect, errcode) {
				return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
			}
			return err
		}
	} else {
		_, err = sq.Exec(fsys.Context, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, {modTime}, TRUE)",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", name),
				sq.TimeParam("modTime", modTime),
			},
		})
		if err != nil {
			if fsys.ErrorCode == nil {
				return err
			}
			errcode := fsys.ErrorCode(err)
			if IsKeyViolation(fsys.Dialect, errcode) {
				return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
			}
			return err
		}
	}
	return nil
}

func (fsys *DatabaseFS) MkdirAll(name string, _ fs.FileMode) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdirall", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil
	}
	tx, err := fsys.DB.BeginTx(fsys.Context, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert the top level directory (no parent), ignoring duplicates.
	modTime := time.Now().UTC()
	segments := strings.Split(name, "/")
	switch fsys.Dialect {
	case "sqlite", "postgres":
		_, err := sq.Exec(fsys.Context, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, creation_time, is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, {modTime}, TRUE)" +
				" ON CONFLICT DO NOTHING",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", segments[0]),
				sq.TimeParam("modTime", modTime),
			},
		})
		if err != nil {
			return err
		}
	case "mysql":
		_, err := sq.Exec(fsys.Context, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, file_path, mod_time, creation_time is_dir)" +
				" VALUES ({fileID}, {filePath}, {modTime}, {modTime}, TRUE)" +
				" ON DUPLICATE KEY UPDATE file_id = file_id",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", segments[0]),
				sq.TimeParam("modTime", modTime),
			},
		})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported dialect %q", fsys.Dialect)
	}

	// Insert the rest of the directories, ignoring duplicates.
	if len(segments) > 1 {
		var preparedExec *sq.PreparedExec
		switch fsys.Dialect {
		case "sqlite", "postgres":
			preparedExec, err = sq.PrepareExec(fsys.Context, tx, sq.Query{
				Dialect: fsys.Dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, {modTime}, TRUE)" +
					" ON CONFLICT DO NOTHING",
				Values: []any{
					sq.Param("fileID", nil),
					sq.Param("parentDir", nil),
					sq.Param("filePath", nil),
					sq.Param("modTime", nil),
				},
			})
			if err != nil {
				return err
			}
		case "mysql":
			preparedExec, err = sq.PrepareExec(fsys.Context, tx, sq.Query{
				Dialect: fsys.Dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir)" +
					" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {modTime}, {modTime}, TRUE)" +
					" ON DUPLICATE KEY UPDATE file_id = file_id",
				Values: []any{
					sq.Param("fileID", nil),
					sq.Param("parentDir", nil),
					sq.Param("filePath", nil),
					sq.Param("modTime", nil),
				},
			})
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported dialect %q", fsys.Dialect)
		}
		defer preparedExec.Close()
		for i := 1; i < len(segments); i++ {
			parentDir := path.Join(segments[:i]...)
			filePath := path.Join(segments[:i+1]...)
			_, err := preparedExec.Exec(fsys.Context,
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", filePath),
				sq.TimeParam("modTime", modTime),
			)
			if err != nil {
				return err
			}
		}
		err = preparedExec.Close()
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (fsys *DatabaseFS) Remove(name string) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") || name == "." {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	file, err := sq.FetchOne(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (file struct {
		fileID      ID
		filePath    string
		isDir       bool
		hasChildren bool
	}) {
		file.fileID = row.UUID("file_id")
		file.filePath = row.String("file_path")
		file.isDir = row.Bool("is_dir")
		file.hasChildren = row.Bool("EXISTS (SELECT 1 FROM files WHERE file_path LIKE {pattern} ESCAPE '\\')", sq.StringParam("pattern", wildcardReplacer.Replace(name)+"/%"))
		return file
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
		}
		return err
	}
	if file.hasChildren {
		return &fs.PathError{Op: "remove", Path: name, Err: syscall.ENOTEMPTY}
	}
	fileType := fileTypes[path.Ext(name)]
	if fileType.IsObject {
		err = fsys.ObjectStorage.Delete(fsys.Context, file.fileID.String()+path.Ext(file.filePath))
		if err != nil {
			return err
		}
	}
	_, err = sq.Exec(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "DELETE FROM pinned_file WHERE (SELECT file_id FROM files WHERE file_path = {name}) IN (parent_id, file_id)",
		Values: []any{
			sq.StringParam("name", name),
		},
	})
	if err != nil {
		return err
	}
	_, err = sq.Exec(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "DELETE FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (fsys *DatabaseFS) RemoveAll(name string) error {
	err := fsys.Context.Err()
	if err != nil {
		return err
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") || name == "." {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	pattern := wildcardReplacer.Replace(name) + "/%"
	cursor, err := sq.FetchCursor(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" WHERE (file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\')" +
			" AND NOT is_dir" +
			" AND (" +
			"file_path LIKE '%.jpeg'" +
			" OR file_path LIKE '%.jpg'" +
			" OR file_path LIKE '%.png'" +
			" OR file_path LIKE '%.webp'" +
			" OR file_path LIKE '%.gif'" +
			")",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	}, func(row *sq.Row) (file struct {
		fileID   ID
		filePath string
	}) {
		file.fileID = row.UUID("file_id")
		file.filePath = row.String("file_path")
		return file
	})
	if err != nil {
		return err
	}
	defer cursor.Close()
	var waitGroup sync.WaitGroup
	for cursor.Next() {
		file, err := cursor.Result()
		if err != nil {
			return err
		}
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			err := fsys.ObjectStorage.Delete(fsys.Context, file.fileID.String()+path.Ext(file.filePath))
			if err != nil {
				fsys.Logger.Error(err.Error())
			}
		}()
	}
	err = cursor.Close()
	if err != nil {
		return err
	}
	waitGroup.Wait()
	_, err = sq.Exec(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format: "DELETE FROM pinned_file WHERE EXISTS (" +
			"SELECT 1"+
			" FROM files"+
			" WHERE (file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\') " +
			" AND files.file_id IN (pinned_file.parent_id, pinned_file.file_id)" +
			")",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	})
	_, err = sq.Exec(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "DELETE FROM files WHERE file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\'",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (fsys *DatabaseFS) Rename(oldName, newName string) error {
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
	exists, err := sq.FetchExists(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT 1 FROM files WHERE file_path = {newName}",
		Values: []any{
			sq.StringParam("newName", newName),
		},
	})
	if exists {
		return &fs.PathError{Op: "rename", Path: newName, Err: fs.ErrExist}
	}
	tx, err := fsys.DB.BeginTx(fsys.Context, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	switch fsys.Dialect {
	case "sqlite", "postgres":
		var updateParent sq.Expression
		if path.Dir(oldName) != path.Dir(newName) {
			// If the parent changes, also update the parent_id.
			updateParent = sq.Expr(", parent_id = (SELECT file_id FROM files WHERE file_path = {})", path.Dir(newName))
		}
		oldNameIsDir, err := sq.FetchOne(fsys.Context, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "UPDATE files SET file_path = {newName}, mod_time = {modTime}{updateParent} WHERE file_path = {oldName} RETURNING {*}",
			Values: []any{
				sq.StringParam("newName", newName),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.Param("updateParent", updateParent),
				sq.StringParam("oldName", oldName),
			},
		}, func(row *sq.Row) bool {
			return row.Bool("is_dir")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
			}
			return err
		}
		if oldNameIsDir {
			_, err := sq.Exec(fsys.Context, tx, sq.Query{
				Dialect: fsys.Dialect,
				Format:  "UPDATE files SET file_path = {filePath}, mod_time = {modTime} WHERE file_path LIKE {pattern} ESCAPE '\\'",
				Values: []any{
					sq.Param("filePath", sq.DialectExpression{
						Default: sq.Expr("{} || substring(file_path, {})", newName, utf8.RuneCountInString(oldName)+1),
						Cases: []sq.DialectCase{{
							Dialect: "mysql",
							Result:  sq.Expr("concat({}, substring(file_path, {}))", newName, utf8.RuneCountInString(oldName)+1),
						}},
					}),
					sq.TimeParam("modTime", time.Now().UTC()),
					sq.StringParam("pattern", wildcardReplacer.Replace(oldName)+"/%"),
				},
			})
			if err != nil {
				return err
			}
		} else {
			if path.Ext(oldName) != path.Ext(newName) {
				return fmt.Errorf("file extension cannot be changed")
			}
		}
	case "mysql":
		oldNameIsDir, err := sq.FetchOne(fsys.Context, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "SELECT {*} FROM files WHERE file_path = {oldName}",
			Values: []any{
				sq.StringParam("oldName", oldName),
			},
		}, func(row *sq.Row) bool {
			return row.Bool("is_dir")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
			}
			return err
		}
		if !oldNameIsDir && path.Ext(oldName) != path.Ext(newName) {
			return fmt.Errorf("file extension cannot be changed")
		}
		var updateParent sq.Expression
		if path.Dir(oldName) != path.Dir(newName) {
			// If the parent changes, also update the parent_id.
			updateParent = sq.Expr(", parent_id = (SELECT file_id FROM files WHERE file_path = {})", path.Dir(newName))
		}
		_, err = sq.Exec(fsys.Context, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "UPDATE files SET file_path = {newName}, mod_time = {modTime}{updateParent} WHERE file_path = {oldName}",
			Values: []any{
				sq.StringParam("newName", newName),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.Param("updateParent", updateParent),
				sq.StringParam("oldName", oldName),
			},
		})
		if err != nil {
			return err
		}
		_, err = sq.Exec(fsys.Context, tx, sq.Query{
			Dialect: fsys.Dialect,
			Format:  "UPDATE files SET file_path = {filePath}, mod_time = {modTime} WHERE file_path LIKE {pattern} ESCAPE '\\'",
			Values: []any{
				sq.Param("filePath", sq.DialectExpression{
					Default: sq.Expr("{} || substring(file_path, {})", newName, utf8.RuneCountInString(oldName)+1),
					Cases: []sq.DialectCase{{
						Dialect: "mysql",
						Result:  sq.Expr("concat({}, substring(file_path, {}))", newName, utf8.RuneCountInString(oldName)+1),
					}},
				}),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("pattern", wildcardReplacer.Replace(oldName)+"/%"),
			},
		})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported dialect %q", fsys.Dialect)
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (fsys *DatabaseFS) Copy(srcName, destName string) error {
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
	var srcFileID ID
	var srcIsDir bool
	var destExists bool
	fileInfos, err := sq.FetchAll(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path IN ({srcName}, {destName})",
		Values: []any{
			sq.StringParam("srcName", srcName),
			sq.StringParam("destName", destName),
		},
	}, func(row *sq.Row) (fileInfo struct {
		FilePath string
		FileID   ID
		IsDir    bool
	}) {
		fileInfo.FilePath = row.String("file_path")
		fileInfo.FileID = row.UUID("file_id")
		fileInfo.IsDir = row.Bool("is_dir")
		return fileInfo
	})
	if err != nil {
		return err
	}
	for _, fileInfo := range fileInfos {
		switch fileInfo.FilePath {
		case srcName:
			srcFileID = fileInfo.FileID
			srcIsDir = fileInfo.IsDir
		case destName:
			destExists = true
		}
	}
	if srcFileID.IsZero() {
		return fs.ErrNotExist
	}
	if destExists {
		return &fs.PathError{Op: "copy", Path: destName, Err: fs.ErrExist}
	}
	if !srcIsDir {
		srcFilePath := srcName
		destFilePath := destName
		destFileID := NewID()
		_, err := sq.Exec(fsys.Context, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
				" SELECT" +
				" {destFileID}" +
				", (SELECT file_id FROM files WHERE file_path = {destParent})" +
				", {destFilePath}" +
				", {modTime}" +
				", {modTime}" +
				", is_dir" +
				", size" +
				", text" +
				", data" +
				" FROM files" +
				" WHERE file_path = {srcFilePath}",
			Values: []any{
				sq.UUIDParam("destFileID", destFileID),
				sq.StringParam("destParent", path.Dir(destFilePath)),
				sq.StringParam("destFilePath", destFilePath),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("srcFilePath", srcFilePath),
			},
		})
		if err != nil {
			return err
		}
		ext := path.Ext(srcFilePath)
		fileType := fileTypes[ext]
		if fileType.IsObject {
			err := fsys.ObjectStorage.Copy(fsys.Context, srcFileID.String()+ext, destFileID.String()+ext)
			if err != nil {
				fsys.Logger.Error(err.Error())
			}
		}
		return nil
	}
	cursor, err := sq.FetchCursor(fsys.Context, fsys.DB, sq.Query{
		Dialect: fsys.Dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {srcName} OR file_path LIKE {pattern} ORDER BY file_path",
		Values: []any{
			sq.StringParam("srcName", srcName),
			sq.StringParam("pattern", wildcardReplacer.Replace(srcName)+"/%"),
		},
	}, func(row *sq.Row) (srcFile struct {
		FileID   ID
		FilePath string
		IsDir    bool
	}) {
		srcFile.FileID = row.UUID("file_id")
		srcFile.FilePath = row.String("file_path")
		srcFile.IsDir = row.Bool("is_dir")
		return srcFile
	})
	if err != nil {
		return err
	}
	defer cursor.Close()
	var wg sync.WaitGroup
	var items [][4]string // destFileID, destParentID, destParent, srcFilePath
	fileIDs := make(map[string]ID)
	for cursor.Next() {
		srcFile, err := cursor.Result()
		if err != nil {
			return nil
		}
		destFileID := NewID()
		destFilePath := destName + strings.TrimPrefix(srcFile.FilePath, srcName)
		fileIDs[destFilePath] = destFileID
		var item [4]string
		item[0] = destFileID.String()
		destParent := path.Dir(destFilePath)
		if destParentID, ok := fileIDs[destParent]; ok {
			item[1] = destParentID.String()
		} else {
			item[2] = destParent
		}
		item[3] = srcFile.FilePath
		items = append(items, item)
		if srcFile.IsDir {
			continue
		}
		ext := path.Ext(srcFile.FilePath)
		fileType := fileTypes[ext]
		if fileType.IsObject {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := fsys.ObjectStorage.Copy(fsys.Context, hex.EncodeToString(srcFile.FileID[:])+ext, hex.EncodeToString(destFileID[:])+ext)
				if err != nil {
					fsys.Logger.Error(err.Error())
				}
			}()
		}
	}
	err = cursor.Close()
	if err != nil {
		return err
	}
	var b strings.Builder
	err = json.NewEncoder(&b).Encode(items)
	if err != nil {
		return err
	}
	switch fsys.Dialect {
	case "sqlite":
		_, err := sq.Exec(fsys.Context, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
				" SELECT" +
				" unhex(items.value->>0, '-') AS dest_file_id" +
				", CASE WHEN items.value->>1 <> '' THEN unhex(items.value->>1, '-') ELSE (SELECT file_id FROM files WHERE file_path = items.value->>2) END AS dest_parent_id" +
				", {destName} || substring(src_files.file_path, {start}) AS dest_file_path" +
				", {modTime}" +
				", {modTime}" +
				", src_files.is_dir" +
				", src_files.size" +
				", src_files.text" +
				", src_files.data" +
				" FROM json_each({items}) AS items" +
				" JOIN files AS src_files ON src_files.file_path = items.value->>3",
			Values: []any{
				sq.StringParam("destName", destName),
				sq.IntParam("start", utf8.RuneCountInString(srcName)+1),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("items", b.String()),
			},
		})
		if err != nil {
			return err
		}
	case "postgres":
		_, err := sq.Exec(fsys.Context, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
				" SELECT" +
				" CAST(items.value->>0 AS UUID) AS dest_file_id" +
				", CASE WHEN items.value->>1 <> '' THEN CAST(items.value->>1 AS UUID) ELSE (SELECT file_id FROM files WHERE file_path = items.value->>2) END AS dest_parent_id" +
				", {destName} || substring(src_files.file_path, {start}) AS dest_file_path" +
				", {modTime}" +
				", {modTime}" +
				", src_files.is_dir" +
				", src_files.size" +
				", src_files.text" +
				", src_files.data" +
				" FROM json_array_elements({items}) AS items" +
				" JOIN files AS src_files ON src_files.file_path = items.value->>3",
			Values: []any{
				sq.StringParam("destName", destName),
				sq.IntParam("start", utf8.RuneCountInString(srcName)+1),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("items", b.String()),
			},
		})
		if err != nil {
			return err
		}
	case "mysql":
		_, err := sq.Exec(fsys.Context, fsys.DB, sq.Query{
			Dialect: fsys.Dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, mod_time, creation_time, is_dir, size, text, data)" +
				" SELECT" +
				" uuid_to_bin(items.dest_file_id) AS dest_file_id" +
				", CASE WHEN items.dest_parent_id <> '' THEN uuid_to_bin(items.dest_parent_id) ELSE (SELECT file_id FROM files WHERE file_path = items.parent_path) END AS dest_parent_id" +
				", concat({destName}, substring(src_files.file_path, {start})) AS dest_file_path" +
				", {modTime}" +
				", {modTime}" +
				", src_files.is_dir" +
				", src_files.size" +
				", src_files.text" +
				", src_files.data" +
				" FROM json_table({items}, '$[*]' COLUMNS (" +
				"dest_file_id VARCHAR(36) PATH '$[0]'" +
				", dest_parent_id VARCHAR(36) PATH '$[1]'" +
				", dest_parent VARCHAR(500) PATH '$[2]'" +
				", src_file_path VARCHAR(500) PATH '$[3]'" +
				")) AS items" +
				" JOIN files AS src_files ON src_files.file_path = items.src_file_path",
			Values: []any{
				sq.StringParam("destName", destName),
				sq.IntParam("start", utf8.RuneCountInString(srcName)+1),
				sq.TimeParam("modTime", time.Now().UTC()),
				sq.StringParam("items", b.String()),
			},
		})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported dialect %q", fsys.Dialect)
	}
	wg.Wait()
	return nil
}

type ObjectStorage interface {
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Put(ctx context.Context, key string, reader io.Reader) error
	Delete(ctx context.Context, key string) error
	Copy(ctx context.Context, srcKey, destKey string) error
}

type S3ObjectStorage struct {
	Client     *s3.Client
	Bucket     string
	PurgeCache func(ctx context.Context, key string) error
	Logger     *slog.Logger
}

var _ ObjectStorage = (*S3ObjectStorage)(nil)

type S3StorageConfig struct {
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	PurgeCache      func(ctx context.Context, key string) error
	Logger          *slog.Logger
}

func NewS3Storage(ctx context.Context, config S3StorageConfig) (*S3ObjectStorage, error) {
	storage := &S3ObjectStorage{
		Client: s3.New(s3.Options{
			BaseEndpoint: aws.String(config.Endpoint),
			Region:       config.Region,
			Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretAccessKey, "")),
		}),
		Bucket:     config.Bucket,
		PurgeCache: config.PurgeCache,
		Logger:     config.Logger,
	}
	// Ping the bucket and see if we have access.
	_, err := storage.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  &storage.Bucket,
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return nil, err
	}
	return storage, nil
}

func (storage *S3ObjectStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	output, err := storage.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "NoSuchKey" {
				return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
			}
		}
		return nil, err
	}
	return output.Body, nil
}

func (storage *S3ObjectStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	fileType, ok := fileTypes[path.Ext(key)]
	if !ok || !fileType.IsObject {
		return fmt.Errorf("%s: invalid filetype %s", key, path.Ext(key))
	}
	cleanup := func(uploadId *string) {
		_, err := storage.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   &storage.Bucket,
			Key:      aws.String(key),
			UploadId: uploadId,
		})
		if err != nil {
			storage.Logger.Error(err.Error())
		}
	}
	createResult, err := storage.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:       &storage.Bucket,
		Key:          aws.String(key),
		CacheControl: aws.String("max-age=31536000, immutable" /* 1 year */),
		ContentType:  aws.String(fileType.ContentType),
	})
	if err != nil {
		return err
	}
	var parts []types.CompletedPart
	var partNumber int32
	var buf [5 << 20]byte // TODO: Is this stack allocated? Would be expensive if not.
	done := false
	for !done {
		n, err := io.ReadFull(reader, buf[:])
		if err != nil {
			if err == io.EOF {
				break
			}
			if err != io.ErrUnexpectedEOF {
				cleanup(createResult.UploadId)
				return err
			}
			done = true
		}
		partNumber++
		uploadResult, err := storage.Client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &storage.Bucket,
			Key:        aws.String(key),
			UploadId:   createResult.UploadId,
			PartNumber: aws.Int32(partNumber),
			Body:       bytes.NewReader(buf[:n]),
		})
		if err != nil {
			cleanup(createResult.UploadId)
			return err
		}
		parts = append(parts, types.CompletedPart{
			ETag:       uploadResult.ETag,
			PartNumber: aws.Int32(partNumber),
		})
	}
	_, err = storage.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &storage.Bucket,
		Key:      aws.String(key),
		UploadId: createResult.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (storage *S3ObjectStorage) Delete(ctx context.Context, key string) error {
	fmt.Printf("S3ObjectStorage.Delete: %s\n", key)
	_, err := storage.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	if storage.PurgeCache != nil {
		err := storage.PurgeCache(ctx, key)
		if err != nil {
			return err
		}
	}
	return nil
}

func (storage *S3ObjectStorage) Copy(ctx context.Context, srcKey, destKey string) error {
	_, err := storage.Client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     &storage.Bucket,
		CopySource: aws.String(srcKey),
		Key:        aws.String(destKey),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "NoSuchKey" {
				return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrNotExist}
			}
		}
		return err
	}
	return nil
}

type InMemoryObjectStorage struct {
	mu      sync.RWMutex
	entries map[string][]byte
}

var _ ObjectStorage = (*InMemoryObjectStorage)(nil)

func NewInMemoryObjectStorage() *InMemoryObjectStorage {
	return &InMemoryObjectStorage{
		mu:      sync.RWMutex{},
		entries: make(map[string][]byte),
	}
}

func (storage *InMemoryObjectStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	storage.mu.RLock()
	value, ok := storage.entries[key]
	storage.mu.RUnlock()
	if !ok {
		return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}

func (storage *InMemoryObjectStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	value, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	storage.mu.Lock()
	storage.entries[key] = value
	storage.mu.Unlock()
	return nil
}

func (storage *InMemoryObjectStorage) Delete(ctx context.Context, key string) error {
	storage.mu.Lock()
	delete(storage.entries, key)
	storage.mu.Unlock()
	return nil
}

func (storage *InMemoryObjectStorage) Copy(ctx context.Context, srcKey, destKey string) error {
	storage.mu.Lock()
	value, ok := storage.entries[srcKey]
	if !ok {
		return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrNotExist}
	}
	storage.entries[destKey] = value
	storage.mu.Unlock()
	return nil
}

type DirObjectStorage struct {
	RootDir string
	TempDir string
}

func NewDirObjectStorage(rootDir, tempDir string) (*DirObjectStorage, error) {
	var err error
	rootDir, err = filepath.Abs(filepath.FromSlash(rootDir))
	if err != nil {
		return nil, err
	}
	tempDir, err = filepath.Abs(filepath.FromSlash(tempDir))
	if err != nil {
		return nil, err
	}
	localStorage := &DirObjectStorage{
		RootDir: filepath.FromSlash(rootDir),
		TempDir: filepath.FromSlash(tempDir),
	}
	return localStorage, nil
}

func (storage *DirObjectStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	err := ctx.Err()
	if err != nil {
		return nil, err
	}
	if len(key) < 4 {
		return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrInvalid}
	}
	file, err := os.Open(filepath.Join(storage.RootDir, key[:4], key))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	return file, nil
}

func (storage *DirObjectStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(key) < 4 {
		return &fs.PathError{Op: "put", Path: key, Err: fs.ErrInvalid}
	}
	if runtime.GOOS == "windows" {
		file, err := os.OpenFile(filepath.Join(storage.RootDir, key[:4], key), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			err = os.Mkdir(filepath.Join(storage.RootDir, key[:4]), 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			file, err = os.OpenFile(filepath.Join(storage.RootDir, key[:4], key), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
		}
		_, err = io.Copy(file, reader)
		if err != nil {
			return err
		}
		return nil
	}
	tempDir := storage.TempDir
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	tempFile, err := os.CreateTemp(tempDir, "__notebrewtemp*__")
	if err != nil {
		return err
	}
	fileInfo, err := tempFile.Stat()
	if err != nil {
		return err
	}
	tempFilePath := filepath.Join(tempDir, fileInfo.Name())
	destFilePath := filepath.Join(storage.RootDir, key[:4], key)
	defer os.Remove(tempFilePath)
	defer tempFile.Close()
	_, err = io.Copy(tempFile, reader)
	if err != nil {
		return err
	}
	err = tempFile.Close()
	if err != nil {
		return err
	}
	err = os.Rename(tempFilePath, destFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		err := os.Mkdir(filepath.Join(storage.RootDir, key[:4]), 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		err = os.Rename(tempFilePath, destFilePath)
		if err != nil {
			return err
		}
	}
	return nil
}

func (storage *DirObjectStorage) Delete(ctx context.Context, key string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(key) < 4 {
		return &fs.PathError{Op: "delete", Path: key, Err: fs.ErrInvalid}
	}
	err = os.Remove(filepath.Join(storage.RootDir, key[:4], key))
	if err != nil {
		return err
	}
	return nil
}

func (storage *DirObjectStorage) Copy(ctx context.Context, srcKey, destKey string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(srcKey) < 4 {
		return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrInvalid}
	}
	if len(destKey) < 4 {
		return &fs.PathError{Op: "copy", Path: destKey, Err: fs.ErrInvalid}
	}
	srcFile, err := os.Open(filepath.Join(storage.RootDir, srcKey[:4], srcKey))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrNotExist}
		}
		return err
	}
	defer srcFile.Close()
	destFile, err := os.OpenFile(filepath.Join(storage.RootDir, destKey[:4], destKey), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
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

func IsKeyViolation(dialect string, errorCode string) bool {
	switch dialect {
	case "sqlite":
		return errorCode == "1555" || errorCode == "2067" // SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE
	case "postgres":
		return errorCode == "23505" // unique_violation
	case "mysql":
		return errorCode == "1062" // ER_DUP_ENTRY
	case "sqlserver":
		return errorCode == "2627"
	default:
		return false
	}
}

func IsForeignKeyViolation(dialect string, errorCode string) bool {
	switch dialect {
	case "sqlite":
		return errorCode == "787" //  SQLITE_CONSTRAINT_FOREIGNKEY
	case "postgres":
		return errorCode == "23503" // foreign_key_violation
	case "mysql":
		return errorCode == "1216" // ER_NO_REFERENCED_ROW
	case "sqlserver":
		return errorCode == "547"
	default:
		return false
	}
}

func isFulltextIndexed(filePath string) bool {
	ext := path.Ext(filePath)
	head, tail, _ := strings.Cut(filePath, "/")
	if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
		head, tail, _ = strings.Cut(tail, "/")
	}
	switch head {
	case "notes":
		return ext == ".html" || ext == ".css" || ext == ".js" || ext == ".md" || ext == ".txt"
	case "pages":
		return ext == ".html"
	case "posts":
		name := path.Base(filePath)
		return name == "post.html" || name == "postlist.html" || ext == ".md"
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		switch next {
		case "posts":
			return false
		case "themes":
			return ext == ".html" || ext == ".css" || ext == ".js" || ext == ".md" || ext == ".txt"
		default:
			return ext == ".css" || ext == ".js" || ext == ".md"
		}
	}
	return false
}
