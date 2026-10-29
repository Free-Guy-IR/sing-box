package hysteria2

import (
	"bytes"
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type capturingVectorisedWriter struct {
	packet []byte
}

func (w *capturingVectorisedWriter) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	for _, buffer := range buffers {
		w.packet = append(w.packet, buffer.Bytes()...)
	}
	return nil
}

type replayPacketConn struct {
	net.PacketConn
	packet []byte
}

func (c *replayPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return copy(p, c.packet), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, nil
}

func TestVectorisedSalamanderWriteOfSeveralBuffers(t *testing.T) {
	obfs := []byte("example-obfs")
	first := bytes.Repeat([]byte{0xaa}, 40)
	second := bytes.Repeat([]byte{0xbb}, 40)
	writer := &capturingVectorisedWriter{}
	conn := &VectorisedSalamanderPacketConn{
		SalamanderPacketConn: SalamanderPacketConn{password: obfs},
		writer:               writer,
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("a vectorised write of two buffers panicked: %v", recovered)
			}
		}()
		err := conn.WriteVectorisedPacket([]*buf.Buffer{buf.As(bytes.Clone(first)), buf.As(bytes.Clone(second))}, M.ParseSocksaddr("127.0.0.1:443"))
		if err != nil {
			t.Fatal(err)
		}
	}()
	reader := &SalamanderPacketConn{PacketConn: &replayPacketConn{packet: writer.packet}, password: obfs}
	plain := make([]byte, len(writer.packet))
	n, _, err := reader.ReadFrom(plain)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(bytes.Clone(first), second...); !bytes.Equal(plain[:n], want) {
		t.Fatalf("the peer decoded %x, want %x", plain[:n], want)
	}
}
