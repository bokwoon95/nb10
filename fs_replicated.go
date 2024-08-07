package nb10

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bokwoon95/nb10/stacktrace"
)

type ReplicatedFSConfig struct {
	Leader                 FS
	Followers              []FS
	SynchronousReplication bool
	Logger                 *slog.Logger
}

type ReplicatedFS struct {
	Leader                 FS
	Followers              []FS
	SynchronousReplication bool
	Logger                 *slog.Logger
	ctx                    context.Context
	baseCtx                context.Context
	baseCtxCancel          func()
	baseCtxWaitGroup       *sync.WaitGroup
}

func NewReplicatedFS(config ReplicatedFSConfig) (*ReplicatedFS, error) {
	baseCtx, baseCtxCancel := context.WithCancel(context.Background())
	replicatedFS := &ReplicatedFS{
		Leader:                 config.Leader,
		Followers:              config.Followers,
		SynchronousReplication: config.SynchronousReplication,
		Logger:                 config.Logger,
		ctx:                    context.Background(),
		baseCtx:                baseCtx,
		baseCtxCancel:          baseCtxCancel,
		baseCtxWaitGroup:       &sync.WaitGroup{},
	}
	return replicatedFS, nil
}

func (fsys *ReplicatedFS) As(target any) bool {
	switch v := fsys.Leader.(type) {
	case interface{ As(any) bool }:
		return v.As(target)
	default:
		return false
	}
}

func (fsys *ReplicatedFS) WithContext(ctx context.Context) FS {
	return &ReplicatedFS{
		Leader:                 fsys.Leader,
		Followers:              fsys.Followers,
		SynchronousReplication: fsys.SynchronousReplication,
		Logger:                 fsys.Logger,
		ctx:                    ctx,
		baseCtx:                fsys.baseCtx,
		baseCtxCancel:          fsys.baseCtxCancel,
		baseCtxWaitGroup:       fsys.baseCtxWaitGroup,
	}
}

func (fsys *ReplicatedFS) WithValues(values map[string]any) FS {
	replicatedFS := &ReplicatedFS{
		Leader:                 fsys.Leader,
		Followers:              append(make([]FS, 0, len(fsys.Followers)), fsys.Followers...),
		SynchronousReplication: fsys.SynchronousReplication,
		Logger:                 fsys.Logger,
		ctx:                    fsys.ctx,
		baseCtx:                fsys.baseCtx,
		baseCtxCancel:          fsys.baseCtxCancel,
		baseCtxWaitGroup:       fsys.baseCtxWaitGroup,
	}
	if v, ok := replicatedFS.Leader.(interface {
		WithValues(map[string]any) FS
	}); ok {
		replicatedFS.Leader = v.WithValues(values)
	}
	for i, follower := range replicatedFS.Followers {
		if v, ok := follower.(interface {
			WithValues(map[string]any) FS
		}); ok {
			replicatedFS.Followers[i] = v.WithValues(values)
		}
	}
	return replicatedFS
}

func (fsys *ReplicatedFS) Open(name string) (fs.File, error) {
	return fsys.Leader.WithContext(fsys.ctx).Open(name)
}

func (fsys *ReplicatedFS) Stat(name string) (fs.FileInfo, error) {
	if statFS, ok := fsys.Leader.WithContext(fsys.ctx).(fs.StatFS); ok {
		return statFS.Stat(name)
	}
	file, err := fsys.Leader.WithContext(fsys.ctx).Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

type ReplicatedFileWriter struct {
	name                   string
	perm                   fs.FileMode
	writer                 io.WriteCloser
	writeFailed            bool
	leader                 FS
	followers              []FS
	synchronousReplication bool
	logger                 *slog.Logger
	ctx                    context.Context
	baseCtx                context.Context
	baseCtxWaitGroup       *sync.WaitGroup
}

func (fsys *ReplicatedFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	writer, err := fsys.Leader.WithContext(fsys.ctx).OpenWriter(name, perm)
	if err != nil {
		return nil, err
	}
	file := &ReplicatedFileWriter{
		name:                   name,
		perm:                   perm,
		writer:                 writer,
		leader:                 fsys.Leader,
		followers:              fsys.Followers,
		synchronousReplication: fsys.SynchronousReplication,
		logger:                 fsys.Logger,
		ctx:                    fsys.ctx,
		baseCtx:                fsys.baseCtx,
		baseCtxWaitGroup:       fsys.baseCtxWaitGroup,
	}
	return file, nil
}

func (file *ReplicatedFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return n, err
	}
	n, err = file.writer.Write(p)
	if err != nil {
		file.writeFailed = true
		return n, err
	}
	return n, err
}

func (file *ReplicatedFileWriter) Close() error {
	if file.writer == nil {
		return fs.ErrClosed
	}
	defer func() {
		file.writer = nil
	}()
	err := file.writer.Close()
	if err != nil {
		return err
	}
	if file.writeFailed {
		return nil
	}
	if file.synchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range file.followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						file.logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				leaderFile, err := file.leader.WithContext(file.ctx).Open(file.name)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
				defer leaderFile.Close()
				writer, err := follower.WithContext(file.ctx).OpenWriter(file.name, file.perm)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
				defer writer.Close()
				_, err = io.Copy(writer, leaderFile)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
				err = writer.Close()
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
		return nil
	}
	for _, follower := range file.followers {
		follower := follower
		file.baseCtxWaitGroup.Add(1)
		go func() {
			defer file.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					file.logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			go func() {
				timer := time.NewTimer(0)
				timer.Stop()
				defer timer.Stop()
				for {
					select {
					case <-file.baseCtx.Done():
						timer.Reset(time.Hour)
					case <-timer.C:
						gracePeriodCancel()
						return
					case <-gracePeriodCtx.Done():
						return
					}
				}
			}()
			leaderFile, err := file.leader.WithContext(gracePeriodCtx).Open(file.name)
			if err != nil {
				file.logger.Error(err.Error())
				return
			}
			defer leaderFile.Close()
			writer, err := follower.WithContext(gracePeriodCtx).OpenWriter(file.name, file.perm)
			if err != nil {
				file.logger.Error(err.Error())
				return
			}
			defer writer.Close()
			_, err = io.Copy(writer, leaderFile)
			if err != nil {
				file.logger.Error(err.Error())
				return
			}
			err = writer.Close()
			if err != nil {
				file.logger.Error(err.Error())
				return
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fsys.Leader.WithContext(fsys.ctx).ReadDir(name)
}

func (fsys *ReplicatedFS) Mkdir(name string, perm fs.FileMode) error {
	err := fsys.Leader.WithContext(fsys.ctx).Mkdir(name, perm)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err := follower.WithContext(fsys.ctx).Mkdir(name, perm)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
		return nil
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			go func() {
				timer := time.NewTimer(0)
				timer.Stop()
				defer timer.Stop()
				for {
					select {
					case <-fsys.baseCtx.Done():
						timer.Reset(time.Hour)
					case <-timer.C:
						gracePeriodCancel()
						return
					case <-gracePeriodCtx.Done():
						return
					}
				}
			}()
			err := follower.WithContext(gracePeriodCtx).Mkdir(name, perm)
			if err != nil {
				fsys.Logger.Error(err.Error())
				return
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) MkdirAll(name string, perm fs.FileMode) error {
	err := fsys.Leader.WithContext(fsys.ctx).MkdirAll(name, perm)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err := follower.WithContext(fsys.ctx).MkdirAll(name, perm)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
		return nil
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			go func() {
				timer := time.NewTimer(0)
				timer.Stop()
				defer timer.Stop()
				for {
					select {
					case <-fsys.baseCtx.Done():
						timer.Reset(time.Hour)
					case <-timer.C:
						gracePeriodCancel()
						return
					case <-gracePeriodCtx.Done():
						return
					}
				}
			}()
			err := follower.WithContext(gracePeriodCtx).Mkdir(name, perm)
			if err != nil {
				fsys.Logger.Error(err.Error())
				return
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) Remove(name string) error {
	err := fsys.Leader.WithContext(fsys.ctx).Remove(name)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err := follower.WithContext(fsys.ctx).Remove(name)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
		return nil
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			go func() {
				timer := time.NewTimer(0)
				timer.Stop()
				defer timer.Stop()
				for {
					select {
					case <-fsys.baseCtx.Done():
						timer.Reset(time.Hour)
					case <-timer.C:
						gracePeriodCancel()
						return
					case <-gracePeriodCtx.Done():
						return
					}
				}
			}()
			err := follower.WithContext(gracePeriodCtx).Remove(name)
			if err != nil {
				fsys.Logger.Error(err.Error())
				return
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) RemoveAll(name string) error {
	err := fsys.Leader.WithContext(fsys.ctx).RemoveAll(name)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err := follower.WithContext(fsys.ctx).RemoveAll(name)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
		return nil
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			go func() {
				timer := time.NewTimer(0)
				timer.Stop()
				defer timer.Stop()
				for {
					select {
					case <-fsys.baseCtx.Done():
						timer.Reset(time.Hour)
					case <-timer.C:
						gracePeriodCancel()
						return
					case <-gracePeriodCtx.Done():
						return
					}
				}
			}()
			err := follower.WithContext(gracePeriodCtx).RemoveAll(name)
			if err != nil {
				fsys.Logger.Error(err.Error())
				return
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) Rename(oldName, newName string) error {
	err := fsys.Leader.WithContext(fsys.ctx).Rename(oldName, newName)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err = follower.WithContext(fsys.ctx).Rename(oldName, newName)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
		return nil
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			go func() {
				timer := time.NewTimer(0)
				timer.Stop()
				defer timer.Stop()
				for {
					select {
					case <-fsys.baseCtx.Done():
						timer.Reset(time.Hour)
					case <-timer.C:
						gracePeriodCancel()
						return
					case <-gracePeriodCtx.Done():
						return
					}
				}
			}()
			err := follower.WithContext(gracePeriodCtx).Rename(oldName, newName)
			if err != nil {
				fsys.Logger.Error(err.Error())
				return
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) Copy(srcName, destName string) error {
	err := fsys.Leader.WithContext(fsys.ctx).Copy(srcName, destName)
	if err != nil {
		return err
	}
	if fsys.SynchronousReplication {
		var errPtr atomic.Pointer[error]
		var waitGroup sync.WaitGroup
		for _, follower := range fsys.Followers {
			follower := follower
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer func() {
					if v := recover(); v != nil {
						fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
					}
				}()
				err = follower.WithContext(fsys.ctx).Copy(srcName, destName)
				if err != nil {
					errPtr.CompareAndSwap(nil, &err)
					return
				}
			}()
		}
		waitGroup.Wait()
		if ptr := errPtr.Load(); ptr != nil {
			return *ptr
		}
		return nil
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fsys.Logger.Error(stacktrace.New(fmt.Errorf("panic: %v", v)).Error())
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			go func() {
				timer := time.NewTimer(0)
				timer.Stop()
				defer timer.Stop()
				for {
					select {
					case <-fsys.baseCtx.Done():
						timer.Reset(time.Hour)
					case <-timer.C:
						gracePeriodCancel()
						return
					case <-gracePeriodCtx.Done():
						return
					}
				}
			}()
			err := follower.WithContext(gracePeriodCtx).Rename(srcName, destName)
			if err != nil {
				fsys.Logger.Error(err.Error())
				return
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) Close() error {
	fsys.baseCtxCancel()
	defer fsys.baseCtxWaitGroup.Wait()
	return nil
}
