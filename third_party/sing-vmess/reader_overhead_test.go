package vmess

import (
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

type readerOverheadConn interface {
	ReaderOverhead() int
}

func assertReaderOverhead(t *testing.T, conn any, want int) {
	t.Helper()
	overheadConn, ok := conn.(readerOverheadConn)
	if !ok {
		t.Fatalf("%T does not report ReaderOverhead, want %d", conn, want)
	}
	if got := overheadConn.ReaderOverhead(); got != want {
		t.Fatalf("%T ReaderOverhead() = %d, want %d", conn, got, want)
	}
}

func TestClientConnsReportReaderOverhead(t *testing.T) {
	destination := M.ParseSocksaddrHostPort("example.com", 443)
	testCases := []struct {
		name     string
		security string
		options  []ClientOption
		packet   bool
		want     int
	}{
		{name: "none stream", security: "none", want: 0},
		{name: "none packet", security: "none", packet: true, want: 0},
		{name: "legacy chunk checksum", security: "aes-128-cfb", want: 4},
		{name: "aes-128-gcm", security: "aes-128-gcm", want: 16},
		{name: "aes-128-gcm packet", security: "aes-128-gcm", packet: true, want: 16},
		{name: "chacha20-poly1305 padded authenticated length", security: "chacha20-poly1305", options: []ClientOption{ClientWithGlobalPadding(), ClientWithAuthenticatedLength()}, want: 16},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client, err := NewClient("b831381d-6324-4d53-ad4f-8cda48b30811", testCase.security, 0, testCase.options...)
			if err != nil {
				t.Fatal(err)
			}
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			var conn any
			if testCase.packet {
				conn = client.DialEarlyPacketConn(local, destination)
			} else {
				conn = client.DialEarlyConn(local, destination)
			}
			assertReaderOverhead(t, conn, testCase.want)
		})
	}
}

func TestServerConnsReportReaderOverhead(t *testing.T) {
	testCases := []struct {
		name     string
		security byte
		option   byte
		packet   bool
		want     int
	}{
		{name: "none plain", security: SecurityTypeNone, want: 0},
		{name: "none chunk stream", security: SecurityTypeNone, option: RequestOptionChunkStream, want: 0},
		{name: "none authenticated length", security: SecurityTypeNone, option: RequestOptionChunkStream | RequestOptionAuthenticatedLength, want: 18},
		{name: "legacy plain", security: SecurityTypeLegacy, want: 0},
		{name: "legacy chunk checksum", security: SecurityTypeLegacy, option: RequestOptionChunkStream, want: 4},
		{name: "aes-128-gcm", security: SecurityTypeAes128Gcm, option: RequestOptionChunkStream | RequestOptionChunkMasking, want: 16},
		{name: "chacha20-poly1305 packet", security: SecurityTypeChacha20Poly1305, option: RequestOptionChunkStream | RequestOptionAuthenticatedLength, packet: true, want: 16},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			raw := rawServerConn{security: testCase.security, option: testCase.option}
			var conn any
			if testCase.packet {
				conn = &serverPacketConn{rawServerConn: raw}
			} else {
				conn = &serverConn{rawServerConn: raw}
			}
			assertReaderOverhead(t, conn, testCase.want)
		})
	}
}
