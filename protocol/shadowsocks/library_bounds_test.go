package shadowsocks_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/common/inbounduser"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type discardHandler struct{}

func (discardHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	return conn.Close()
}

func (discardHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return conn.Close()
}

func (discardHandler) NewError(ctx context.Context, err error) {}

type userUpdater interface {
	UpdateUsersWithPasswords(userList []inbounduser.Identity, passwordList []string) error
	NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error
}

func raceUpdatesAgainstConnections(t *testing.T, service userUpdater, credential func(int) string) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := range 200 {
			count := round%3 + 1
			names := make([]string, count)
			credentials := make([]string, count)
			for index := range count {
				names[index] = fmt.Sprint("user-", index)
				credentials[index] = credential(round + index)
			}
			_ = service.UpdateUsersWithPasswords(inbounduser.Names(names), credentials)
		}
	}()
	for range 200 {
		client, server := net.Pipe()
		go func() {
			junk := make([]byte, 128)
			_, _ = rand.Read(junk)
			_, _ = client.Write(junk)
			_ = client.Close()
		}()
		_ = service.NewConnection(context.Background(), server, M.Metadata{})
		_ = server.Close()
	}
	wg.Wait()
}

func TestAEADReaderRefusesAChunkLongerThanItsBuffer(t *testing.T) {
	t.Parallel()
	block, err := aes.NewCipher(make([]byte, 16))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	lengthChunk := aead.Seal(nil, make([]byte, aead.NonceSize()), []byte{0xff, 0xff}, nil)
	reader := shadowaead.NewReader(bytes.NewReader(lengthChunk), aead, shadowaead.MaxPacketSize)
	require.NotPanics(t, func() {
		_, err = reader.Read(make([]byte, 64))
	})
	require.Error(t, err)
}

func TestAEADMultiServiceUserUpdatesRacingConnections(t *testing.T) {
	service, err := shadowaead.NewMultiService[inbounduser.Identity]("aes-128-gcm", 60, discardHandler{})
	require.NoError(t, err)
	raceUpdatesAgainstConnections(t, service, func(seed int) string {
		return fmt.Sprint("credential-", seed)
	})
}

func TestAEAD2022MultiServiceUserUpdatesRacingConnections(t *testing.T) {
	key := func(seed int) string {
		return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(seed)}, 16))
	}
	service, err := shadowaead_2022.NewMultiServiceWithPassword[inbounduser.Identity]("2022-blake3-aes-128-gcm", key(255), 60, discardHandler{}, nil)
	require.NoError(t, err)
	raceUpdatesAgainstConnections(t, service, key)
}
