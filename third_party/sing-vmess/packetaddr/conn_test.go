package packetaddr

import (
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

type readerOverheadConn interface {
	ReaderOverhead() int
}

func assertSocksaddrReaderOverhead(t *testing.T, conn any) {
	t.Helper()
	overheadConn, ok := conn.(readerOverheadConn)
	if !ok {
		t.Fatalf("%T does not report ReaderOverhead, want %d", conn, M.MaxIPSocksaddrLength)
	}
	if got := overheadConn.ReaderOverhead(); got != M.MaxIPSocksaddrLength {
		t.Fatalf("%T ReaderOverhead() = %d, want %d", conn, got, M.MaxIPSocksaddrLength)
	}
}

func TestBindConnReportsReaderOverhead(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	assertSocksaddrReaderOverhead(t, NewBindConn(local))
}

func TestPacketConnReportsReaderOverhead(t *testing.T) {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	assertSocksaddrReaderOverhead(t, NewConn(udpConn, M.ParseSocksaddrHostPort("127.0.0.1", 53)))
}
