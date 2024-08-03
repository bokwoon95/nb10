package nb10

import (
	"context"
	"sync"
)

type ReplicatedFS struct {
	Leader            FS
	Followers         []FS
	leaderCtx         context.Context
	followerCtx       context.Context // TODO: wait up to 1 hour for all followers to finish following the calling of followerCancel()
	followerCancel    func()
	followerWaitGroup sync.WaitGroup
}
