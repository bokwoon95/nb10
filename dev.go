//go:build dev
// +build dev

package nb10

import (
	"os"
)

func init() {
	RuntimeFS = os.DirFS(".")
	logSessions = true
}
