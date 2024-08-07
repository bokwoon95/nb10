//go:build darwin || freebsd || netbsd

package nb10

import (
	"io/fs"
	"syscall"
	"time"
)

func CreationTime(absolutePath string, fileInfo fs.FileInfo) time.Time {
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}
	}
	return time.Unix(stat.Birthtimespec.Sec, stat.Birthtimespec.Nsec).UTC()
}
