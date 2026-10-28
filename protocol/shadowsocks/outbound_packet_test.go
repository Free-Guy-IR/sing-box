package shadowsocks_test

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func packetConnReceiving(t *testing.T, datagram []byte) N.NetPacketConn {
	t.Helper()
	method, err := shadowsocks.CreateMethod(context.Background(), "aes-128-ctr", shadowsocks.MethodOptions{Password: "example-outbound"})
	require.NoError(t, err)
	local, remote := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})
	go func() {
		_, _ = remote.Write(datagram)
	}()
	return method.DialPacketConn(local)
}

func TestStreamCipherPacketConnRefusesADatagramShorterThanTheSalt(t *testing.T) {
	t.Parallel()
	short := []byte{1, 2, 3, 4}
	var err error
	buffer := buf.NewPacket()
	defer buffer.Release()
	require.NotPanics(t, func() {
		_, err = packetConnReceiving(t, short).ReadPacket(buffer)
	})
	require.Error(t, err)
	require.NotPanics(t, func() {
		_, _, err = packetConnReceiving(t, short).ReadFrom(make([]byte, 64))
	})
	require.Error(t, err)
}
