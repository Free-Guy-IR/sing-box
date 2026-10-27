package hysteria2

import (
	"testing"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
)

func TestAuthenticationRacingAStreamDispatch(t *testing.T) {
	for range 10 {
		f := newAuthRemovalFixture(t)
		start := make(chan struct{})
		dispatched := make(chan bool, 1)
		go func() {
			<-start
			handled, _ := f.session.dispatchStream(http3.FrameType(0x01), nil, nil)
			dispatched <- handled
		}()
		authenticated := make(chan int, 1)
		go func() {
			<-start
			authenticated <- <-f.authenticate("alice-secret")
		}()
		close(start)
		if status := receive(t, "authentication", authenticated); status != protocol.StatusAuthOK {
			t.Fatalf("the authentication answered %d", status)
		}
		if receive(t, "dispatch", dispatched) {
			t.Fatal("a non-proxy frame was handled by the dispatcher")
		}
	}
}

func TestConcurrentAuthenticationsKeepOneCredential(t *testing.T) {
	for range 10 {
		f := newAuthRemovalFixture(t)
		f.service.userAccess.Lock()
		f.service.userMap["bob-secret"] = 2
		f.service.userAccess.Unlock()
		start := make(chan struct{})
		statuses := make(chan int, 2)
		for _, password := range []string{"alice-secret", "bob-secret"} {
			go func() {
				<-start
				statuses <- <-f.authenticate(password)
			}()
		}
		close(start)
		for range 2 {
			if status := receive(t, "authentication", statuses); status != protocol.StatusAuthOK {
				t.Fatalf("an authentication answered %d", status)
			}
		}
		password := f.registeredPassword()
		f.service.sessionAccess.Lock()
		user := f.session.authUser
		f.service.sessionAccess.Unlock()
		if f.users()[password] != user {
			t.Fatalf("the session registered the credential %q but carries user %d", password, user)
		}
	}
}
