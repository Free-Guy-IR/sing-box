package vless_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/inbounduser"
	"github.com/sagernet/sing-vmess"
	singVLESS "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

type testUser struct {
	name string
	uuid uuid.UUID
}

type contextRecorder struct {
	contexts chan context.Context
}

func (r *contextRecorder) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	select {
	case r.contexts <- ctx:
	default:
	}
	conn.Close()
}

func (r *contextRecorder) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
}

func newTestUser(name string) testUser {
	return testUser{name: name, uuid: uuid.Must(uuid.NewV4())}
}

func updateUsers(service *singVLESS.Service[inbounduser.Identity], users []testUser) {
	service.UpdateUsers(
		inbounduser.Identities(users, func(it testUser) string {
			return it.name
		}),
		common.Map(users, func(it testUser) string {
			return it.uuid.String()
		}),
		make([]string, len(users)),
	)
}

func authenticate(t *testing.T, recorder *contextRecorder, service *singVLESS.Service[inbounduser.Identity], user testUser) context.Context {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_ = singVLESS.WriteRequest(client, singVLESS.Request{
			UUID:        [16]byte(user.uuid),
			Command:     vmess.CommandTCP,
			Destination: M.ParseSocksaddr("example.com:443"),
		}, nil)
	}()
	go func() {
		_ = service.NewConnection(context.Background(), server, M.ParseSocksaddr("127.0.0.1:12345"), nil)
	}()
	select {
	case ctx := <-recorder.contexts:
		return ctx
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for authenticated connection")
		return nil
	}
}

func TestIdentitySurvivesShiftedUserSet(t *testing.T) {
	t.Parallel()
	alice := newTestUser("alice")
	bob := newTestUser("bob")
	carol := newTestUser("carol")

	recorder := &contextRecorder{contexts: make(chan context.Context, 1)}
	service := singVLESS.NewService[inbounduser.Identity](logger.NOP(), recorder)
	updateUsers(service, []testUser{alice, bob, carol})

	ctx := authenticate(t, recorder, service, bob)

	shifted := []testUser{bob, carol}
	updateUsers(service, shifted)

	identity, loaded := auth.UserFromContext[inbounduser.Identity](ctx)
	require.True(t, loaded)
	require.Equal(t, "bob", identity.Name)
	require.Equal(t, "bob", identity.Label())
	require.Equal(t, "carol", shifted[identity.Index].name)
}

func TestIdentitySurvivesShrunkUserSet(t *testing.T) {
	t.Parallel()
	alice := newTestUser("alice")
	bob := newTestUser("bob")
	carol := newTestUser("carol")

	recorder := &contextRecorder{contexts: make(chan context.Context, 1)}
	service := singVLESS.NewService[inbounduser.Identity](logger.NOP(), recorder)
	updateUsers(service, []testUser{alice, bob, carol})

	ctx := authenticate(t, recorder, service, carol)

	shrunk := []testUser{carol}
	updateUsers(service, shrunk)

	identity, loaded := auth.UserFromContext[inbounduser.Identity](ctx)
	require.True(t, loaded)
	require.Equal(t, "carol", identity.Name)
	require.GreaterOrEqual(t, identity.Index, len(shrunk))
}

func TestRemovedUserCannotAuthenticateAgain(t *testing.T) {
	t.Parallel()
	alice := newTestUser("alice")
	bob := newTestUser("bob")

	recorder := &contextRecorder{contexts: make(chan context.Context, 1)}
	service := singVLESS.NewService[inbounduser.Identity](logger.NOP(), recorder)
	updateUsers(service, []testUser{alice, bob})
	updateUsers(service, []testUser{bob})

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_ = singVLESS.WriteRequest(client, singVLESS.Request{
			UUID:        [16]byte(alice.uuid),
			Command:     vmess.CommandTCP,
			Destination: M.ParseSocksaddr("example.com:443"),
		}, nil)
	}()
	err := service.NewConnection(context.Background(), server, M.ParseSocksaddr("127.0.0.1:12345"), nil)
	require.Error(t, err)
}

func TestConcurrentUserUpdatesKeepIdentityCorrect(t *testing.T) {
	t.Parallel()
	alice := newTestUser("alice")
	bob := newTestUser("bob")
	carol := newTestUser("carol")

	recorder := &contextRecorder{contexts: make(chan context.Context, 1)}
	service := singVLESS.NewService[inbounduser.Identity](logger.NOP(), recorder)
	updateUsers(service, []testUser{alice, bob, carol})

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
			switch round % 3 {
			case 0:
				updateUsers(service, []testUser{alice, bob, carol})
			case 1:
				updateUsers(service, []testUser{bob, carol})
			default:
				updateUsers(service, []testUser{bob})
			}
		}
	}()

	for range 50 {
		ctx := authenticate(t, recorder, service, bob)
		identity, loaded := auth.UserFromContext[inbounduser.Identity](ctx)
		require.True(t, loaded)
		require.Equal(t, "bob", identity.Name)
	}

	close(stop)
	wg.Wait()
}
