package trojan_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/trojan"
	trojanTransport "github.com/sagernet/sing-box/transport/trojan"

	"github.com/stretchr/testify/require"
)

type trojanUserUpdater interface {
	UpdateUsers(users []option.TrojanUser) error
}

func sharedPasswordUsers() []option.TrojanUser {
	return []option.TrojanUser{
		{Name: "alice", Password: "shared"},
		{Name: "bob", Password: "shared"},
	}
}

func TestNewInboundRejectsSharedPasswordWithoutPanic(t *testing.T) {
	var err error
	require.NotPanics(t, func() {
		_, err = trojan.NewInbound(context.Background(), nil, log.NewNOPFactory().Logger(), "trojan-in", option.TrojanInboundOptions{
			Users: sharedPasswordUsers(),
		})
	})
	require.ErrorIs(t, err, trojanTransport.ErrUserExists)
	require.EqualError(t, err, "user already exists: password used by alice")
}

func TestUpdateUsersRejectsSharedPasswordWithoutPanic(t *testing.T) {
	inbound, err := trojan.NewInbound(context.Background(), nil, log.NewNOPFactory().Logger(), "trojan-in", option.TrojanInboundOptions{
		Users: []option.TrojanUser{{Name: "alice", Password: "pw-a"}},
	})
	require.NoError(t, err)
	updater, ok := inbound.(trojanUserUpdater)
	require.True(t, ok)

	require.NotPanics(t, func() {
		err = updater.UpdateUsers(sharedPasswordUsers())
	})
	require.ErrorIs(t, err, trojanTransport.ErrUserExists)
	require.EqualError(t, err, "user already exists: password used by alice")
	require.NoError(t, updater.UpdateUsers([]option.TrojanUser{{Name: "alice", Password: "pw-a"}, {Name: "bob", Password: "pw-b"}}))
}
