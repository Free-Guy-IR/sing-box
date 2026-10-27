package tuic

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

func waitLockWaiters(t *testing.T, frame string, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stacks := make([]byte, 1<<20)
		stacks = stacks[:runtime.Stack(stacks, true)]
		waiters := 0
		for _, goroutine := range strings.Split(string(stacks), "\n\n") {
			header, frames, _ := strings.Cut(goroutine, "\n")
			if strings.Contains(frames, frame) && strings.Contains(header, "[sync.Mutex.Lock") {
				waiters++
			}
		}
		if waiters >= count {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("fewer than %d goroutines in %s are waiting on a lock", count, frame)
}

func TestConcurrentAuthenticationsOnOneConnection(t *testing.T) {
	f := newAuthRemovalFixture(t)
	type outcome struct {
		err      error
		panicked any
	}
	outcomes := make(chan outcome, 2)
	f.service.sessionAccess.Lock()
	for range 2 {
		serverStream := f.authStream(t)
		go func() {
			var current outcome
			defer func() {
				current.panicked = recover()
				outcomes <- current
			}()
			current.err = f.session.handleUniStream(serverStream)
		}()
	}
	waitLockWaiters(t, authenticateFrame, 2)
	f.service.sessionAccess.Unlock()

	var accepted, refused int
	for range 2 {
		current := receive(t, "authentication", outcomes)
		switch {
		case current.panicked != nil:
			t.Fatalf("a second authentication on the same connection panicked: %v", current.panicked)
		case current.err == nil:
			accepted++
		case strings.Contains(current.err.Error(), "multiple authentication requests"):
			refused++
		default:
			t.Fatalf("unexpected authentication error: %v", current.err)
		}
	}
	if accepted != 1 || refused != 1 {
		t.Fatalf("accepted %d and refused %d authentications, want one of each", accepted, refused)
	}
	if !f.registered() {
		t.Fatal("the accepted authentication was not registered")
	}
}
