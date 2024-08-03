package nb10

import (
	"context"
	"sync"
)

type ReplicatedFS struct {
	Leader            FS
	Followers         []FS
	leaderCtx         context.Context
	followerCtx       context.Context
	followerCancel    func()
	followerWaitGroup sync.WaitGroup
}
