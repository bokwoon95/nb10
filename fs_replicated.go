package nb10

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type ReplicatedFSConfig struct {
	Leader      FS
	Followers   []FS
	Synchronous bool
	Logger      *slog.Logger
}

type ReplicatedFS struct {
	Leader           FS
	Followers        []FS
	Synchronous      bool
	Logger           *slog.Logger
	operationsCtx    context.Context
	baseCtx          context.Context
	baseCtxCancel    func()
	baseCtxWaitGroup *sync.WaitGroup
}

func NewReplicatedFS(config ReplicatedFSConfig) (*ReplicatedFS, error) {
	baseCtx, baseCtxCancel := context.WithCancel(context.Background())
	replicatedFS := &ReplicatedFS{
		Leader:           config.Leader,
		Followers:        config.Followers,
		Synchronous:      config.Synchronous,
		Logger:           config.Logger,
		operationsCtx:    context.Background(),
		baseCtx:          baseCtx,
		baseCtxCancel:    baseCtxCancel,
		baseCtxWaitGroup: &sync.WaitGroup{},
	}
	return replicatedFS, nil
}

func (fsys *ReplicatedFS) As(target any) bool {
	if v, ok := fsys.Leader.(interface {
		As(target any) bool
	}); ok {
		if v.As(target) {
			return true
		}
	}
	return false
}

func (fsys *ReplicatedFS) WithContext(ctx context.Context) FS {
	// return &ReplicatedFS{
	// 	Leader:        fsys.Leader,
	// 	Followers:     fsys.Followers,
	// 	Synchronous:   fsys.Synchronous,
	// 	Logger:        fsys.Logger,
	// 	operationsCtx: ctx,
	// 	baseCtx:       fsys.baseCtx,
	// 	baseCtxCancel: fsys.baseCtxCancel,
	// 	waitGroup:     fsys.waitGroup,
	// }
	return nil
}

func (fsys *ReplicatedFS) WithValues(values map[string]any) FS {
	replicatedFS := &ReplicatedFS{
		Leader:           fsys.Leader,
		Followers:        append(make([]FS, 0, len(fsys.Followers)), fsys.Followers...),
		Synchronous:      fsys.Synchronous,
		Logger:           fsys.Logger,
		operationsCtx:    fsys.operationsCtx,
		baseCtx:          fsys.baseCtx,
		baseCtxCancel:    fsys.baseCtxCancel,
		baseCtxWaitGroup: fsys.baseCtxWaitGroup,
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
	// return replicatedFS
	return nil
}

func (fsys *ReplicatedFS) Open(name string) (fs.File, error) {
	return fsys.Leader.Open(name)
}

func (fsys *ReplicatedFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	// TODO: No!! We need a custom replicatedFS writer that wraps the leader's
	// writecloser and replicates the write to the rest of the writers when
	// Close() is called.
	return fsys.Leader.OpenWriter(name, perm)
}

func (fsys *ReplicatedFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fsys.Leader.ReadDir(name)
}

func (fsys *ReplicatedFS) Mkdir(name string, perm fs.FileMode) error {
	err := fsys.Leader.Mkdir(name, perm)
	if err != nil {
		return err
	}
	if fsys.Synchronous {
		group, groupctx := errgroup.WithContext(fsys.operationsCtx)
		for _, follower := range fsys.Followers {
			follower := follower
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				return follower.WithContext(groupctx).Mkdir(name, perm)
			})
		}
		return group.Wait()
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fmt.Println("panic: " + string(debug.Stack()))
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			gracePeriodTimer := time.NewTimer(time.Hour)
			defer gracePeriodTimer.Stop()
			go func() {
				<-fsys.baseCtx.Done()
				<-gracePeriodTimer.C
				gracePeriodCancel()
			}()
			err := follower.WithContext(gracePeriodCtx).Mkdir(name, perm)
			if err != nil {
				fsys.Logger.Error(err.Error())
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) MkdirAll(name string, perm fs.FileMode) error {
	err := fsys.Leader.MkdirAll(name, perm)
	if err != nil {
		return err
	}
	if fsys.Synchronous {
		group, groupctx := errgroup.WithContext(fsys.operationsCtx)
		for _, follower := range fsys.Followers {
			follower := follower
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				return follower.WithContext(groupctx).MkdirAll(name, perm)
			})
		}
		return group.Wait()
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fmt.Println("panic: " + string(debug.Stack()))
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			gracePeriodTimer := time.NewTimer(time.Hour)
			defer gracePeriodTimer.Stop()
			go func() {
				<-fsys.baseCtx.Done()
				<-gracePeriodTimer.C
				gracePeriodCancel()
			}()
			err := follower.WithContext(gracePeriodCtx).Mkdir(name, perm)
			if err != nil {
				fsys.Logger.Error(err.Error())
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) Remove(name string) error {
	err := fsys.Leader.Remove(name)
	if err != nil {
		return err
	}
	if fsys.Synchronous {
		group, groupctx := errgroup.WithContext(fsys.operationsCtx)
		for _, follower := range fsys.Followers {
			follower := follower
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				return follower.WithContext(groupctx).Remove(name)
			})
		}
		return group.Wait()
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fmt.Println("panic: " + string(debug.Stack()))
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			gracePeriodTimer := time.NewTimer(time.Hour)
			defer gracePeriodTimer.Stop()
			go func() {
				<-fsys.baseCtx.Done()
				<-gracePeriodTimer.C
				gracePeriodCancel()
			}()
			err := follower.WithContext(gracePeriodCtx).Remove(name)
			if err != nil {
				fsys.Logger.Error(err.Error())
			}
		}()
	}
	return nil
}

func (fsys *ReplicatedFS) RemoveAll(name string) error {
	err := fsys.Leader.RemoveAll(name)
	if err != nil {
		return err
	}
	if fsys.Synchronous {
		group, groupctx := errgroup.WithContext(fsys.operationsCtx)
		for _, follower := range fsys.Followers {
			follower := follower
			group.Go(func() (err error) {
				defer func() {
					if v := recover(); v != nil {
						err = fmt.Errorf("panic: " + string(debug.Stack()))
					}
				}()
				return follower.WithContext(groupctx).RemoveAll(name)
			})
		}
		return group.Wait()
	}
	for _, follower := range fsys.Followers {
		follower := follower
		fsys.baseCtxWaitGroup.Add(1)
		go func() {
			defer fsys.baseCtxWaitGroup.Done()
			defer func() {
				if v := recover(); v != nil {
					fmt.Println("panic: " + string(debug.Stack()))
				}
			}()
			gracePeriodCtx, gracePeriodCancel := context.WithCancel(context.Background())
			defer gracePeriodCancel()
			gracePeriodTimer := time.NewTimer(time.Hour)
			defer gracePeriodTimer.Stop()
			go func() {
				<-fsys.baseCtx.Done()
				<-gracePeriodTimer.C
				gracePeriodCancel()
			}()
			err := follower.WithContext(gracePeriodCtx).RemoveAll(name)
			if err != nil {
				fsys.Logger.Error(err.Error())
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
