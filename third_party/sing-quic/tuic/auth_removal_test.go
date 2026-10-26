package tuic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/logger"
)

func listenLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newTestQUICPair(t *testing.T) (*quic.Conn, *quic.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := quic.Listen(listenLoopbackUDP(t), &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"tuic-test"},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type acceptResult struct {
		conn *quic.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept(ctx)
		accepted <- acceptResult{conn, acceptErr}
	}()
	client, err := quic.Dial(ctx, listenLoopbackUDP(t), listener.Addr(), &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		NextProtos: []string{"tuic-test"},
	}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	t.Cleanup(func() { _ = result.conn.CloseWithError(0, "") })
	return result.conn, client
}

const (
	authenticateFrame = "tuic.(*serverSession[...]).handleUniStream("
	updateUsersFrame  = "tuic.(*Service[...]).UpdateUsers("
)

var aliceUUID = [16]byte{0xa1, 0x1c, 0xe0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

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
	server  *quic.Conn
	client  *quic.Conn
}

func newAuthRemovalFixture(t *testing.T) *authRemovalFixture {
	t.Helper()
	serverQUIC, clientQUIC := newTestQUICPair(t)
	service := &Service[int]{
		ctx:         context.Background(),
		logger:      logger.NOP(),
		userMap:     map[[16]byte]int{aliceUUID: 1},
		passwordMap: map[int]string{1: "alice-secret"},
		sessions:    make(map[*serverSession[int]]struct{}),
	}
	session := &serverSession[int]{
		Service:    service,
		ctx:        service.ctx,
		quicConn:   serverQUIC,
		connDone:   make(chan struct{}),
		authDone:   make(chan struct{}),
		udpConnMap: make(map[uint16]*udpPacketConn),
	}
	service.addSession(session)
	return &authRemovalFixture{service: service, session: session, server: serverQUIC, client: clientQUIC}
}

func (f *authRemovalFixture) authenticate(t *testing.T) chan error {
	t.Helper()
	state := f.client.ConnectionState()
	token, err := state.TLS.ExportKeyingMaterial(string(aliceUUID[:]), []byte("alice-secret"), 32)
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte{Version, CommandAuthenticate}, aliceUUID[:]...)
	request = append(request, token...)
	clientStream, err := f.client.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = clientStream.Write(request); err != nil {
		t.Fatal(err)
	}
	if err = clientStream.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverStream, err := f.server.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- f.session.handleUniStream(serverStream)
	}()
	return result
}

func (f *authRemovalFixture) update(users map[[16]byte]int, passwords map[int]string) chan struct{} {
	var userList []int
	var uuidList [][16]byte
	var passwordList []string
	for userUUID, user := range users {
		userList = append(userList, user)
		uuidList = append(uuidList, userUUID)
		passwordList = append(passwordList, passwords[user])
	}
	done := make(chan struct{})
	go func() {
		f.service.UpdateUsers(userList, uuidList, passwordList)
		close(done)
	}()
	return done
}

func (f *authRemovalFixture) users() map[[16]byte]int {
	f.service.userAccess.RLock()
	defer f.service.userAccess.RUnlock()
	return f.service.userMap
}

func (f *authRemovalFixture) registered() bool {
	f.service.sessionAccess.Lock()
	defer f.service.sessionAccess.Unlock()
	return f.session.authSet
}

func (f *authRemovalFixture) closed() bool {
	select {
	case <-f.session.connDone:
		return true
	default:
		return false
	}
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
	authenticated := f.authenticate(t)
	authenticationWait := lockWaitOf(t, authenticateFrame)
	removed := f.update(nil, nil)
	removalWait := lockWaitOf(t, updateUsersFrame)
	f.service.sessionAccess.Unlock()

	if authenticationWait != "sync.Mutex.Lock" {
		t.Fatalf("the authentication was not parked registering its credential: %s", authenticationWait)
	}
	if removalWait != "sync.RWMutex.Lock" {
		t.Errorf("the removal swapped the user map (it then waited on %s) while an authentication that had matched the removed uuid was not registered yet, so its session scan could not see it", removalWait)
	}
	if err := receive(t, "authentication", authenticated); err != nil {
		t.Fatal(err)
	}
	receive(t, "removal", removed)
	if users := f.users(); len(users) != 0 {
		t.Fatalf("the removal was lost: users %v", users)
	}
	if !f.closed() {
		t.Fatal("the removed user's session is still open after the removal returned")
	}
}

func TestRemovalBeforeLookupRejectsTheAuthentication(t *testing.T) {
	f := newAuthRemovalFixture(t)
	f.service.sessionAccess.Lock()
	removed := f.update(nil, nil)
	removalWait := lockWaitOf(t, updateUsersFrame)
	if removalWait != "sync.Mutex.Lock" {
		f.service.sessionAccess.Unlock()
		t.Fatalf("the removal was not parked scanning sessions after swapping the user map: %s", removalWait)
	}
	err := receive(t, "authentication", f.authenticate(t))
	f.service.sessionAccess.Unlock()
	receive(t, "removal", removed)

	if err == nil || !strings.Contains(err.Error(), "authentication: unknown user") {
		t.Fatalf("a uuid removed before its lookup was not rejected: %v", err)
	}
	if f.registered() {
		t.Fatal("a uuid removed before its lookup was registered")
	}
	select {
	case <-f.session.authDone:
		t.Fatal("a uuid removed before its lookup completed the authentication")
	default:
	}
	if users := f.users(); len(users) != 0 {
		t.Fatalf("the removal was lost: users %v", users)
	}
}

func TestUpdateKeepingTheUserDuringAuthenticationIsAppliedAndKeepsTheSession(t *testing.T) {
	bobUUID := [16]byte{0xb0, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	f := newAuthRemovalFixture(t)
	f.service.sessionAccess.Lock()
	authenticated := f.authenticate(t)
	authenticationWait := lockWaitOf(t, authenticateFrame)
	updated := f.update(map[[16]byte]int{aliceUUID: 1, bobUUID: 2}, map[int]string{1: "alice-secret", 2: "bob-secret"})
	lockWaitOf(t, updateUsersFrame)
	f.service.sessionAccess.Unlock()

	if authenticationWait != "sync.Mutex.Lock" {
		t.Fatalf("the authentication was not parked registering its credential: %s", authenticationWait)
	}
	if err := receive(t, "authentication", authenticated); err != nil {
		t.Fatal(err)
	}
	receive(t, "update", updated)
	users := f.users()
	if len(users) != 2 || users[aliceUUID] != 1 || users[bobUUID] != 2 {
		t.Fatalf("the update was lost: users %v", users)
	}
	if !f.registered() {
		t.Fatal("the kept user's credential was not registered")
	}
	if f.closed() {
		t.Fatal("an update that kept the user closed the session")
	}
}
