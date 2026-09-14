package vless_test

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-vmess"
	singVLESS "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

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
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for a routed sub-stream")
		return ""
	}
}

func vlessUser(name string) option.VLESSUser {
	return option.VLESSUser{Name: name, UUID: uuid.Must(uuid.NewV4()).String()}
}

func writeMuxNewTCPStream(t *testing.T, conn net.Conn, sessionID uint16, destination M.Socksaddr) {
	t.Helper()
	frame := buf.New()
	defer frame.Release()
	require.NoError(t, binary.Write(frame, binary.BigEndian, uint16(4+1+vmess.AddressSerializer.AddrPortLen(destination))))
	require.NoError(t, binary.Write(frame, binary.BigEndian, sessionID))
	require.NoError(t, frame.WriteByte(vmess.StatusNew))
	require.NoError(t, frame.WriteByte(0))
	require.NoError(t, frame.WriteByte(vmess.NetworkTCP))
	require.NoError(t, vmess.AddressSerializer.WriteAddrPort(frame, destination))
	_, err := conn.Write(frame.Bytes())
	require.NoError(t, err)
}

func startMuxSession(t *testing.T, inbound adapter.Inbound, user option.VLESSUser) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
	})
	handler, ok := inbound.(adapter.TCPInjectableInbound)
	require.True(t, ok)
	go handler.NewConnectionEx(context.Background(), server, adapter.InboundContext{
		Source: M.ParseSocksaddr("127.0.0.1:12345"),
	}, nil)
	userUUID := uuid.Must(uuid.FromString(user.UUID))
	require.NoError(t, singVLESS.WriteRequest(client, singVLESS.Request{
		UUID:    [16]byte(userUUID),
		Command: vmess.CommandMux,
	}, nil))
	return client
}

func newTestVLESSInbound(t *testing.T, recorder *routedUserRecorder, users []option.VLESSUser) adapter.Inbound {
	t.Helper()
	created, err := vless.NewInbound(context.Background(), recorder, log.NewNOPFactory().Logger(), "vless-in", option.VLESSInboundOptions{
		Users: users,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		created.Close()
	})
	return created
}

func TestMuxSubstreamAttributionSurvivesShiftedUserSet(t *testing.T) {
	t.Parallel()
	alice := vlessUser("alice")
	bob := vlessUser("bob")
	carol := vlessUser("carol")

	recorder := newRoutedUserRecorder()
	created := newTestVLESSInbound(t, recorder, []option.VLESSUser{alice, bob, carol})

	client := startMuxSession(t, created, bob)

	writeMuxNewTCPStream(t, client, 1, M.ParseSocksaddr("example.com:443"))
	require.Equal(t, "bob", recorder.await(t))

	reloader, ok := created.(interface {
		UpdateUsers([]option.VLESSUser) error
	})
	require.True(t, ok)
	require.NoError(t, reloader.UpdateUsers([]option.VLESSUser{bob, carol}))

	writeMuxNewTCPStream(t, client, 2, M.ParseSocksaddr("example.org:443"))
	require.Equal(t, "bob", recorder.await(t))
}

func TestConcurrentHotReloadDuringMuxSubstreams(t *testing.T) {
	t.Parallel()
	alice := vlessUser("alice")
	bob := vlessUser("bob")
	carol := vlessUser("carol")

	recorder := newRoutedUserRecorder()
	created := newTestVLESSInbound(t, recorder, []option.VLESSUser{alice, bob, carol})

	client := startMuxSession(t, created, bob)

	reloader, ok := created.(interface {
		UpdateUsers([]option.VLESSUser) error
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
				_ = reloader.UpdateUsers([]option.VLESSUser{alice, bob, carol})
			} else {
				_ = reloader.UpdateUsers([]option.VLESSUser{carol, bob, alice})
			}
		}
	}()

	for sessionID := uint16(1); sessionID <= 40; sessionID++ {
		writeMuxNewTCPStream(t, client, sessionID, M.ParseSocksaddr("example.com:443"))
		require.Equal(t, "bob", recorder.await(t))
	}

	close(stop)
	wg.Wait()
}

func TestMuxSubstreamAttributionSurvivesShrunkUserSet(t *testing.T) {
	t.Parallel()
	alice := vlessUser("alice")
	bob := vlessUser("bob")
	carol := vlessUser("carol")

	recorder := newRoutedUserRecorder()
	created := newTestVLESSInbound(t, recorder, []option.VLESSUser{alice, bob, carol})

	client := startMuxSession(t, created, carol)

	writeMuxNewTCPStream(t, client, 1, M.ParseSocksaddr("example.com:443"))
	require.Equal(t, "carol", recorder.await(t))

	reloader, ok := created.(interface {
		UpdateUsers([]option.VLESSUser) error
	})
	require.True(t, ok)
	require.NoError(t, reloader.UpdateUsers([]option.VLESSUser{carol}))

	writeMuxNewTCPStream(t, client, 2, M.ParseSocksaddr("example.org:443"))
	require.Equal(t, "carol", recorder.await(t))
}
