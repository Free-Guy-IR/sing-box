package shadowtls_test

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type pipeDialer struct {
	conn net.Conn
}

func (d pipeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (d pipeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type closingHandler struct{}

func (closingHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
}

func tlsRecord(contentType byte, payload []byte) []byte {
	return append([]byte{contentType, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func TestV2HandshakeHashUnderConcurrentServerTraffic(t *testing.T) {
	for range 20 {
		serveV2Handshake(t)
	}
}

func serveV2Handshake(t *testing.T) {
	t.Helper()
	handshakeServer, handshakeClient := net.Pipe()
	service, err := shadowtls.NewService(shadowtls.ServiceConfig{
		Version:  2,
		Password: "example-shadowtls",
		Handshake: shadowtls.HandshakeConfig{
			Server: M.ParseSocksaddr("127.0.0.1:443"),
			Dialer: pipeDialer{handshakeClient},
		},
		Handler: closingHandler{},
		Logger:  logger.NOP(),
	})
	require.NoError(t, err)
	client, server := net.Pipe()
	served := make(chan error, 1)
	go func() {
		served <- service.NewConnection(context.Background(), server, M.Socksaddr{}, M.Socksaddr{}, nil)
	}()
	go func() {
		_, _ = io.Copy(io.Discard, handshakeServer)
	}()
	go func() {
		for range 200 {
			if _, writeErr := handshakeServer.Write(tlsRecord(0x17, make([]byte, 32))); writeErr != nil {
				return
			}
		}
	}()
	go func() {
		_, _ = io.Copy(io.Discard, client)
	}()
	_, err = client.Write(tlsRecord(0x16, make([]byte, 40)))
	require.NoError(t, err)
	for range 3 {
		_, err = client.Write(tlsRecord(0x17, make([]byte, 16)))
		require.NoError(t, err)
	}
	_ = client.Close()
	_ = handshakeServer.Close()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the ShadowTLS v2 service never returned")
	}
}
