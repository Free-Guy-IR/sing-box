package tuic

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func udpFragment(id uint8, payload []byte) *udpMessage {
	message := allocMessage()
	message.sessionID = 1
	message.packetID = 7
	message.fragmentTotal = 2
	message.fragmentID = id
	message.destination = M.ParseSocksaddr("127.0.0.1:53")
	message.data = buf.As(payload)
	return message
}

func TestDefragmentsFragmentsLongerThanUint16InTotal(t *testing.T) {
	first := bytes.Repeat([]byte{0xaa}, 40000)
	second := bytes.Repeat([]byte{0xbb}, 40000)
	defragger := newUDPDefragger()
	if assembled := defragger.feed(udpFragment(0, first)); assembled != nil {
		t.Fatal("the first of two fragments was returned as a whole packet")
	}
	var assembled *udpMessage
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("reassembling two 40000-byte fragments panicked: %v", recovered)
			}
		}()
		assembled = defragger.feed(udpFragment(1, second))
	}()
	if assembled == nil {
		t.Fatal("the second fragment did not complete the packet")
	}
	defer assembled.releaseMessage()
	if !bytes.Equal(assembled.data.Bytes(), append(append([]byte{}, first...), second...)) {
		t.Fatalf("the reassembled packet has %d bytes, want the 80000 bytes of both fragments in order", assembled.data.Len())
	}
}
