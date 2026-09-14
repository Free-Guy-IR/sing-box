package trojan_test

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/inbounduser"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type testUser struct {
	name     string
	password string
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

func updateUsers(service *trojan.Service[inbounduser.Identity], users []testUser) error {
	return service.UpdateUsers(
		inbounduser.Identities(users, func(it testUser) string {
			return it.name
		}),
		common.Map(users, func(it testUser) string {
			return it.password
		}),
	)
}

func requestBytes(password string) []byte {
	key := trojan.Key(password)
	buffer := buf.New()
	defer buffer.Release()
	common.Must1(buffer.Write(key[:]))
	common.Must1(buffer.Write([]byte{'\r', '\n'}))
	common.Must(buffer.WriteByte(trojan.CommandTCP))
	common.Must(M.SocksaddrSerializer.WriteAddrPort(buffer, M.ParseSocksaddr("example.com:443")))
	common.Must1(buffer.Write([]byte{'\r', '\n'}))
	return bytes.Clone(buffer.Bytes())
}

func authenticate(t *testing.T, recorder *contextRecorder, service *trojan.Service[inbounduser.Identity], user testUser) context.Context {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	request := requestBytes(user.password)
	go func() {
		_, _ = client.Write(request)
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
	alice := testUser{name: "alice", password: "pw-a"}
	bob := testUser{name: "bob", password: "pw-b"}
	carol := testUser{name: "carol", password: "pw-c"}

	recorder := &contextRecorder{contexts: make(chan context.Context, 1)}
	service := trojan.NewService[inbounduser.Identity](recorder, nil, logger.NOP())
	require.NoError(t, updateUsers(service, []testUser{alice, bob, carol}))

	ctx := authenticate(t, recorder, service, bob)

	shifted := []testUser{bob, carol}
	require.NoError(t, updateUsers(service, shifted))

	identity, loaded := auth.UserFromContext[inbounduser.Identity](ctx)
	require.True(t, loaded)
	require.Equal(t, "bob", identity.Name)
	require.Equal(t, "bob", identity.Label())
	require.Equal(t, "carol", shifted[identity.Index].name)
}

func TestUnnamedUsersDoNotCollide(t *testing.T) {
	t.Parallel()
	recorder := &contextRecorder{contexts: make(chan context.Context, 1)}
	service := trojan.NewService[inbounduser.Identity](recorder, nil, logger.NOP())
	require.NoError(t, updateUsers(service, []testUser{
		{password: "pw-1"},
		{password: "pw-2"},
	}))

	ctx := authenticate(t, recorder, service, testUser{password: "pw-2"})
	identity, loaded := auth.UserFromContext[inbounduser.Identity](ctx)
	require.True(t, loaded)
	require.Equal(t, "1", identity.Label())
}

func TestConcurrentUserUpdatesKeepIdentityCorrect(t *testing.T) {
	t.Parallel()
	alice := testUser{name: "alice", password: "pw-a"}
	bob := testUser{name: "bob", password: "pw-b"}
	carol := testUser{name: "carol", password: "pw-c"}

	recorder := &contextRecorder{contexts: make(chan context.Context, 1)}
	service := trojan.NewService[inbounduser.Identity](recorder, nil, logger.NOP())
	require.NoError(t, updateUsers(service, []testUser{alice, bob, carol}))

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
				_ = updateUsers(service, []testUser{alice, bob, carol})
			case 1:
				_ = updateUsers(service, []testUser{bob, carol})
			default:
				_ = updateUsers(service, []testUser{bob})
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
