package tuic_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/tuic"
	qtls "github.com/sagernet/sing-quic"
	singTUIC "github.com/sagernet/sing-quic/tuic"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

var loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})

type routedUserRecorder struct {
	users chan string
}

func newRoutedUserRecorder() *routedUserRecorder {
	return &routedUserRecorder{users: make(chan string, 8)}
}

func (r *routedUserRecorder) Start(stage adapter.StartStage) error {
	return nil
}

func (r *routedUserRecorder) Close() error {
	return nil
}

func (r *routedUserRecorder) PreMatch(metadata adapter.InboundContext, directRouteContext tun.DirectRouteContext, timeout time.Duration, supportBypass bool) (tun.DirectRouteDestination, error) {
	return nil, os.ErrInvalid
}

func (r *routedUserRecorder) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	r.record(metadata.User)
	conn.Close()
	return nil
}

func (r *routedUserRecorder) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	r.record(metadata.User)
	conn.Close()
	return nil
}

func (r *routedUserRecorder) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.record(metadata.User)
	conn.Close()
}

func (r *routedUserRecorder) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.record(metadata.User)
	conn.Close()
}

func (r *routedUserRecorder) RuleSet(tag string) (adapter.RuleSet, bool) {
	return nil, false
}

func (r *routedUserRecorder) Rules() []adapter.Rule {
	return nil
}

func (r *routedUserRecorder) NeedFindProcess() bool {
	return false
}

func (r *routedUserRecorder) AppendTracker(tracker adapter.ConnectionTracker) {
}

func (r *routedUserRecorder) ResetNetwork() {
}

func (r *routedUserRecorder) record(user string) {
	select {
	case r.users <- user:
	default:
	}
}

func (r *routedUserRecorder) await(t *testing.T) string {
	t.Helper()
	select {
	case user := <-r.users:
		return user
	case <-time.After(20 * time.Second):
		t.Fatal("timeout waiting for a routed stream")
		return ""
	}
}

func (r *routedUserRecorder) awaitNone(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case user := <-r.users:
		t.Fatal("traffic of a removed user was attributed to ", user)
	case <-time.After(within):
	}
}

func tuicTestUser(name string, secret string) option.TUICUser {
	return option.TUICUser{
		Name:     name,
		UUID:     uuid.Must(uuid.NewV4()).String(),
		Password: secret,
	}
}

func reserveUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback.AsSlice()})
	require.NoError(t, err)
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	require.NoError(t, conn.Close())
	return port
}

func newTestTUICInbound(t *testing.T, recorder *routedUserRecorder, users []option.TUICUser) (adapter.Inbound, M.Socksaddr) {
	t.Helper()
	port := reserveUDPPort(t)
	created, err := tuic.NewInbound(context.Background(), recorder, log.NewNOPFactory().Logger(), "tuic-in", option.TUICInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(loopback)),
			ListenPort: port,
		},
		Users:       users,
		AuthTimeout: badoption.Duration(20 * time.Second),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:    true,
				Insecure:   true,
				ServerName: "example.org",
				ALPN:       badoption.Listable[string]{"h3"},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, created.Start(adapter.StartStateStart))
	t.Cleanup(func() {
		created.Close()
	})
	return created, M.SocksaddrFrom(loopback, port)
}

func updateTUICUsers(t *testing.T, created adapter.Inbound, users []option.TUICUser) {
	t.Helper()
	reloader, ok := created.(interface {
		UpdateUsers([]option.TUICUser) error
	})
	require.True(t, ok)
	require.NoError(t, reloader.UpdateUsers(users))
}

type tuicTestSession struct {
	conn *quic.Conn
}

func dialTUICSession(t *testing.T, server M.Socksaddr, user option.TUICUser) *tuicTestSession {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: loopback.AsSlice()})
	require.NoError(t, err)
	t.Cleanup(func() {
		udpConn.Close()
	})
	tlsConfig, err := tls.NewClient(context.Background(), log.NewNOPFactory().Logger(), "example.org", option.OutboundTLSOptions{
		Enabled:    true,
		Insecure:   true,
		ServerName: "example.org",
		ALPN:       badoption.Listable[string]{"h3"},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	quicConn, err := qtls.Dial(ctx, udpConn, server.UDPAddr(), tlsConfig, &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingUniStreams: 1 << 60,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		quicConn.CloseWithError(0, "")
	})
	session := &tuicTestSession{conn: quicConn}
	session.authenticate(t, user)
	return session
}

func (s *tuicTestSession) authenticate(t *testing.T, user option.TUICUser) {
	t.Helper()
	userUUID := uuid.Must(uuid.FromString(user.UUID))
	handshakeState := s.conn.ConnectionState()
	token, err := handshakeState.TLS.ExportKeyingMaterial(string(userUUID[:]), []byte(user.Password), 32)
	require.NoError(t, err)
	stream, err := s.conn.OpenUniStream()
	require.NoError(t, err)
	request := buf.NewSize(singTUIC.AuthenticateLen)
	defer request.Release()
	common.Must(request.WriteByte(singTUIC.Version))
	common.Must(request.WriteByte(singTUIC.CommandAuthenticate))
	common.Must1(request.Write(userUUID[:]))
	common.Must1(request.Write(token))
	_, err = stream.Write(request.Bytes())
	require.NoError(t, err)
	require.NoError(t, stream.Close())
}

func (s *tuicTestSession) connectRequest(t *testing.T, destination M.Socksaddr) []byte {
	t.Helper()
	request := buf.New()
	defer request.Release()
	common.Must(request.WriteByte(singTUIC.Version))
	common.Must(request.WriteByte(singTUIC.CommandConnect))
	common.Must(singTUIC.AddressSerializer.WriteAddrPort(request, destination))
	return append([]byte(nil), request.Bytes()...)
}

func (s *tuicTestSession) openStream(t *testing.T, destination M.Socksaddr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := s.conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = stream.Write(s.connectRequest(t, destination))
	require.NoError(t, err)
}

func (s *tuicTestSession) tryOpenStream(t *testing.T, destination M.Socksaddr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return
	}
	_, _ = stream.Write(s.connectRequest(t, destination))
}

func (s *tuicTestSession) awaitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-s.conn.Context().Done():
	case <-time.After(20 * time.Second):
		t.Fatal("session of a removed user stayed open")
	}
}

func TestQUICSessionAttributionSurvivesShiftedUserSet(t *testing.T) {
	t.Parallel()
	aaron := tuicTestUser("aaron", "pw-d")
	alice := tuicTestUser("alice", "pw-a")
	bob := tuicTestUser("bob", "pw-b")
	carol := tuicTestUser("carol", "pw-c")

	recorder := newRoutedUserRecorder()
	created, serverAddr := newTestTUICInbound(t, recorder, []option.TUICUser{alice, bob, carol})

	session := dialTUICSession(t, serverAddr, bob)

	session.openStream(t, M.ParseSocksaddr("example.com:443"))
	require.Equal(t, "bob", recorder.await(t))

	updateTUICUsers(t, created, []option.TUICUser{aaron, alice, bob, carol})

	session.openStream(t, M.ParseSocksaddr("example.org:443"))
	require.Equal(t, "bob", recorder.await(t))
}

func TestQUICSessionAttributionSurvivesShrunkUserSet(t *testing.T) {
	t.Parallel()
	alice := tuicTestUser("alice", "pw-a")
	bob := tuicTestUser("bob", "pw-b")
	carol := tuicTestUser("carol", "pw-c")

	recorder := newRoutedUserRecorder()
	created, serverAddr := newTestTUICInbound(t, recorder, []option.TUICUser{alice, bob, carol})

	session := dialTUICSession(t, serverAddr, carol)

	session.openStream(t, M.ParseSocksaddr("example.com:443"))
	require.Equal(t, "carol", recorder.await(t))

	updateTUICUsers(t, created, []option.TUICUser{carol})

	session.openStream(t, M.ParseSocksaddr("example.org:443"))
	require.Equal(t, "carol", recorder.await(t))
}

func TestRemovedUserSessionIsClosedAndNeverReattributed(t *testing.T) {
	t.Parallel()
	alice := tuicTestUser("alice", "pw-a")
	bob := tuicTestUser("bob", "pw-b")
	carol := tuicTestUser("carol", "pw-c")

	recorder := newRoutedUserRecorder()
	created, serverAddr := newTestTUICInbound(t, recorder, []option.TUICUser{alice, bob, carol})

	session := dialTUICSession(t, serverAddr, bob)

	session.openStream(t, M.ParseSocksaddr("example.com:443"))
	require.Equal(t, "bob", recorder.await(t))

	updateTUICUsers(t, created, []option.TUICUser{alice, carol})

	session.awaitClosed(t)

	session.tryOpenStream(t, M.ParseSocksaddr("example.org:443"))
	recorder.awaitNone(t, 3*time.Second)
}

func TestConcurrentUserUpdatesDuringQUICStreams(t *testing.T) {
	t.Parallel()
	alice := tuicTestUser("alice", "pw-a")
	bob := tuicTestUser("bob", "pw-b")
	carol := tuicTestUser("carol", "pw-c")

	recorder := newRoutedUserRecorder()
	created, serverAddr := newTestTUICInbound(t, recorder, []option.TUICUser{alice, bob, carol})

	session := dialTUICSession(t, serverAddr, bob)

	reloader, ok := created.(interface {
		UpdateUsers([]option.TUICUser) error
	})
	require.True(t, ok)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := 0; ; round++ {
			select {
			case <-stop:
				return
			default:
			}
			if round%2 == 0 {
				_ = reloader.UpdateUsers([]option.TUICUser{alice, bob, carol})
			} else {
				_ = reloader.UpdateUsers([]option.TUICUser{bob, alice, carol})
			}
			time.Sleep(time.Millisecond)
		}
	}()

	for range 30 {
		session.openStream(t, M.ParseSocksaddr("example.com:443"))
		require.Equal(t, "bob", recorder.await(t))
	}

	close(stop)
	wg.Wait()
}
