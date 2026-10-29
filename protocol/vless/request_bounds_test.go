package vless_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/sagernet/sing-box/common/inbounduser"
	singVLESS "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func requestWithAddon(addonHeader byte, declaredLength uint64) []byte {
	addon := append([]byte{addonHeader}, binary.AppendUvarint(nil, declaredLength)...)
	request := []byte{singVLESS.Version}
	request = append(request, bytes.Repeat([]byte{0x5a}, 16)...)
	request = append(request, byte(len(addon)))
	return append(request, addon...)
}

func TestRequestWithAnAddonLongerThanItsDataIsRefusedBeforeAuthentication(t *testing.T) {
	t.Parallel()
	for name, addonHeader := range map[string]byte{"flow": (1 << 3) | 2, "seed": (2 << 3) | 2} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			service := singVLESS.NewService[inbounduser.Identity](logger.NOP(), &contextRecorder{contexts: make(chan context.Context, 1)})
			updateUsers(service, []testUser{newTestUser("alice")})
			client, server := net.Pipe()
			defer client.Close()
			go func() {
				_, _ = client.Write(requestWithAddon(addonHeader, 1<<62))
			}()
			var err error
			require.NotPanics(t, func() {
				err = service.NewConnection(context.Background(), server, M.ParseSocksaddr("127.0.0.1:1234"), nil)
			})
			require.Error(t, err)
		})
	}
}
