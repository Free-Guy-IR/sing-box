package vless

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

func exactSlice(parts ...[]byte) []byte {
	joined := bytes.Join(parts, nil)
	return joined[:len(joined):len(joined)]
}

func unPadded(t *testing.T, conn *VisionConn, chunk []byte) []byte {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("unPadding panicked: %v", recovered)
		}
	}()
	var content []byte
	for _, buffer := range conn.unPadding(chunk) {
		content = append(content, buffer.Bytes()...)
		buffer.Release()
	}
	return content
}

func TestUnPaddingAcrossASplitPaddingHeader(t *testing.T) {
	userUUID := [16]byte{0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a}
	conn := &VisionConn{logger: logger.NOP(), userUUID: userUUID, remainingContent: -1, remainingPadding: -1}
	first := unPadded(t, conn, exactSlice(userUUID[:], []byte{0x00, 0x00, 0x02, 0x00, 0x00}, []byte("hi"), []byte{0x01, 0x00, 0x03}))
	second := unPadded(t, conn, exactSlice([]byte{0x00, 0x00}, []byte("end")))
	if got := string(first) + string(second); got != "hiend" {
		t.Fatalf("unpadded %q, want %q", got, "hiend")
	}
}

func TestFilterTLSWithASessionIDLongerThanTheRecord(t *testing.T) {
	serverHello := make([]byte, 79)
	copy(serverHello, []byte{22, 3, 3, 0x01, 0x00, 2})
	serverHello[43] = 0xff
	conn := &VisionConn{logger: logger.NOP(), numberOfPacketToFilter: 8}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("filterTLS panicked: %v", recovered)
		}
	}()
	conn.filterTLS([][]byte{serverHello[:len(serverHello):len(serverHello)]})
}
