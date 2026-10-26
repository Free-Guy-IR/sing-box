package hysteria2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common/logger"
)

const (
	authenticateFrame = "hysteria2.(*serverSession[...]).ServeHTTP("
	updateUsersFrame  = "hysteria2.(*Service[...]).UpdateUsers("
)

func lockWaitOf(t *testing.T, frame string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stacks := make([]byte, 1<<20)
		stacks = stacks[:runtime.Stack(stacks, true)]
		for _, goroutine := range strings.Split(string(stacks), "\n\n") {
			header, frames, _ := strings.Cut(goroutine, "\n")
			if !strings.Contains(frames, frame) {
				continue
			}
			_, state, _ := strings.Cut(header, "[")
			state, _, _ = strings.Cut(state, "]")
			state, _, _ = strings.Cut(state, ",")
			if strings.HasPrefix(state, "sync.") {
				return state
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("no goroutine in %s is waiting on a lock", frame)
	return ""
}

type authRemovalFixture struct {
	service *Service[int]
	session *serverSession[int]
	conn    *quic.Conn
}

func newAuthRemovalFixture(t *testing.T) *authRemovalFixture {
	t.Helper()
	serverQUIC, _ := newTestQUICPair(t, &quic.Config{})
	service := &Service[int]{
		ctx:               context.Background(),
		logger:            logger.NOP(),
		userMap:           map[string]int{"alice-secret": 1},
		udpDisabled:       true,
		masqueradeHandler: http.NotFoundHandler(),
		sessions:          make(map[*serverSession[int]]struct{}),
	}
	session := &serverSession[int]{
		Service:    service,
		ctx:        service.ctx,
		quicConn:   serverQUIC,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	service.addSession(session)
	return &authRemovalFixture{service: service, session: session, conn: serverQUIC}
}

func (f *authRemovalFixture) authenticate(password string) chan int {
	request := httptest.NewRequest(http.MethodPost, "https://"+protocol.URLHost+protocol.URLPath, nil)
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: password})
	status := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		f.session.ServeHTTP(recorder, request)
		status <- recorder.Code
	}()
	return status
}

func (f *authRemovalFixture) update(users map[string]int) chan struct{} {
	var userList []int
	var passwordList []string
	for password, user := range users {
		userList = append(userList, user)
		passwordList = append(passwordList, password)
	}
	done := make(chan struct{})
	go func() {
		f.service.UpdateUsers(userList, passwordList)
		close(done)
	}()
	return done
}

func (f *authRemovalFixture) users() map[string]int {
	f.service.userAccess.RLock()
	defer f.service.userAccess.RUnlock()
	return f.service.userMap
}

func (f *authRemovalFixture) registeredPassword() string {
	f.service.sessionAccess.Lock()
	defer f.service.sessionAccess.Unlock()
	return f.session.authPassword
}

func receive[T any](t *testing.T, name string, channel chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(5 * time.Second):
		t.Fatalf("the %s never finished", name)
		var zero T
		return zero
	}
}

func TestRemovalDuringAuthenticationClosesTheSession(t *testing.T) {
	f := newAuthRemovalFixture(t)
	f.service.sessionAccess.Lock()
	authenticated := f.authenticate("alice-secret")
	authenticationWait := lockWaitOf(t, authenticateFrame)
	removed := f.update(nil)
	removalWait := lockWaitOf(t, updateUsersFrame)
	f.service.sessionAccess.Unlock()

	if authenticationWait != "sync.Mutex.Lock" {
		t.Fatalf("the authentication was not parked registering its credential: %s", authenticationWait)
	}
	if removalWait != "sync.RWMutex.Lock" {
		t.Errorf("the removal swapped the user map (it then waited on %s) while an authentication that had matched the removed password was not registered yet, so its session scan could not see it", removalWait)
	}
	if status := receive(t, "authentication", authenticated); status != protocol.StatusAuthOK {
		t.Fatalf("the authentication answered %d", status)
	}
	receive(t, "removal", removed)
	if users := f.users(); len(users) != 0 {
		t.Fatalf("the removal was lost: users %v", users)
	}
	if f.conn.Context().Err() == nil {
		t.Fatal("the removed user's connection is still open after the removal returned")
	}
}

func TestRemovalBeforeLookupRejectsTheAuthentication(t *testing.T) {
	f := newAuthRemovalFixture(t)
	f.service.sessionAccess.Lock()
	removed := f.update(nil)
	removalWait := lockWaitOf(t, updateUsersFrame)
	if removalWait != "sync.Mutex.Lock" {
		f.service.sessionAccess.Unlock()
		t.Fatalf("the removal was not parked scanning sessions after swapping the user map: %s", removalWait)
	}
	status := receive(t, "authentication", f.authenticate("alice-secret"))
	f.service.sessionAccess.Unlock()
	receive(t, "removal", removed)

	if status != http.StatusNotFound {
		t.Fatalf("a password removed before its lookup answered %d", status)
	}
	if f.session.authenticated {
		t.Fatal("a password removed before its lookup authenticated the session")
	}
	if password := f.registeredPassword(); password != "" {
		t.Fatalf("a password removed before its lookup was registered: %q", password)
	}
	if users := f.users(); len(users) != 0 {
		t.Fatalf("the removal was lost: users %v", users)
	}
}

func TestUpdateKeepingTheUserDuringAuthenticationIsAppliedAndKeepsTheSession(t *testing.T) {
	f := newAuthRemovalFixture(t)
	f.service.sessionAccess.Lock()
	authenticated := f.authenticate("alice-secret")
	authenticationWait := lockWaitOf(t, authenticateFrame)
	updated := f.update(map[string]int{"alice-secret": 1, "bob-secret": 2})
	lockWaitOf(t, updateUsersFrame)
	f.service.sessionAccess.Unlock()

	if authenticationWait != "sync.Mutex.Lock" {
		t.Fatalf("the authentication was not parked registering its credential: %s", authenticationWait)
	}
	if status := receive(t, "authentication", authenticated); status != protocol.StatusAuthOK {
		t.Fatalf("the authentication answered %d", status)
	}
	receive(t, "update", updated)
	users := f.users()
	if len(users) != 2 || users["alice-secret"] != 1 || users["bob-secret"] != 2 {
		t.Fatalf("the update was lost: users %v", users)
	}
	if password := f.registeredPassword(); password != "alice-secret" {
		t.Fatalf("the kept user's credential was not registered: %q", password)
	}
	if err := f.conn.Context().Err(); err != nil {
		t.Fatalf("an update that kept the user closed the session: %v", err)
	}
}
