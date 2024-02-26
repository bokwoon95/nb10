//go:build !windows && !linux && !darwin && !freebsd && !netbsd

package nb10

import (
	"io/fs"
	"time"
)

func CreationTime(absolutePath string, fileInfo fs.FileInfo) time.Time {
	return time.Time{}
}
