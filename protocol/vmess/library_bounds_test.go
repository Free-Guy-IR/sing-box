package vmess_test

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestChecksumReaderRefusesAChunkShorterThanTheChecksum(t *testing.T) {
	t.Parallel()
	var err error
	require.NotPanics(t, func() {
		_, err = vmess.NewStreamChecksumReader(bytes.NewReader([]byte{1, 2})).Read(make([]byte, 16))
	})
	require.Error(t, err)
	buffer := buf.New()
	defer buffer.Release()
	require.NotPanics(t, func() {
		err = vmess.NewStreamChecksumReader(bytes.NewReader([]byte{1, 2})).ReadBuffer(buffer)
	})
	require.Error(t, err)
}

func TestChunkWriterReleasesItsLockAfterAFailedWrite(t *testing.T) {
	t.Parallel()
	writer := vmess.NewStreamChunkWriter(failingWriter{}, nil, nil)
	_, err := writer.Write([]byte("first"))
	require.Error(t, err)
	second := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write([]byte("second"))
		second <- writeErr
	}()
	select {
	case err = <-second:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("a write after a failed write never returned")
	}
}

func TestXUDPConnRefusesAFrameShorterThanItsHeader(t *testing.T) {
	t.Parallel()
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	go func() {
		_, _ = remote.Write([]byte{0x00, 0x00, 0x00, 0x01, vmess.StatusKeep, 0x00})
	}()
	buffer := buf.NewPacket()
	defer buffer.Release()
	var err error
	require.NotPanics(t, func() {
		_, err = vmess.NewXUDPConn(local, M.ParseSocksaddr("127.0.0.1:53")).ReadPacket(buffer)
	})
	require.Error(t, err)
}
