//go:build linux

package nb10

import (
	"io/fs"
	"time"

	"golang.org/x/sys/unix"
)

func CreationTime(absolutePath string, fileInfo fs.FileInfo) time.Time {
	if absolutePath == "" {
		return time.Time{}
	}
	var statx unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, absolutePath, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &statx)
	if err != nil {
		return time.Time{}
	}
	if statx.Mask&unix.STATX_BTIME != unix.STATX_BTIME {
		return time.Time{}
	}
	return time.Unix(statx.Btime.Sec, int64(statx.Btime.Nsec)).UTC()
}
