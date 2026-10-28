package hysteria2

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/quicvarint"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func fqdnOfLength(length int) string {
	return strings.Repeat("a", length-4) + ".com"
}

func withoutPanic(t *testing.T, name string, call func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", name, recovered)
		}
	}()
	call()
}

func newDatagramConn(t *testing.T) (*udpPacketConn, *quic.Conn) {
	t.Helper()
	serverQUIC, clientQUIC := newTestQUICPair(t, &quic.Config{EnableDatagrams: true})
	return newUDPPacketConn(context.Background(), serverQUIC, func() {}), clientQUIC
}

func receiveDatagram(t *testing.T, clientQUIC *quic.Conn) *udpMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	datagram, err := clientQUIC.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	message := allocMessage()
	if err = decodeUDPMessage(message, datagram); err != nil {
		t.Fatal(err)
	}
	return message
}

func TestUDPWritePacketRefusesAnFQDNLongerThan255(t *testing.T) {
	conn, clientQUIC := newDatagramConn(t)
	for _, length := range []int{1500, 256} {
		var err error
		withoutPanic(t, "WritePacket", func() {
			err = conn.WritePacket(buf.As([]byte("payload")), M.Socksaddr{Fqdn: fqdnOfLength(length), Port: 53})
		})
		if err == nil || !strings.Contains(err.Error(), "fqdn too long") {
			t.Fatalf("a %d-character destination was not refused: %v", length, err)
		}
	}
	destination := M.Socksaddr{Fqdn: fqdnOfLength(255), Port: 53}
	if err := conn.WritePacket(buf.As([]byte("payload")), destination); err != nil {
		t.Fatal(err)
	}
	if message := receiveDatagram(t, clientQUIC); message.destination != destination.String() {
		t.Fatalf("the client received destination %q", message.destination)
	}
}

func TestUDPWriteToRefusesAnFQDNLongerThan255(t *testing.T) {
	conn, _ := newDatagramConn(t)
	for _, length := range []int{1500, 256} {
		var err error
		withoutPanic(t, "WriteTo", func() {
			_, err = conn.WriteTo([]byte("payload"), M.Socksaddr{Fqdn: fqdnOfLength(length), Port: 53})
		})
		if err == nil || !strings.Contains(err.Error(), "fqdn too long") {
			t.Fatalf("a %d-character destination was not refused: %v", length, err)
		}
	}
}

func TestUDPWritePacketWithAnMTUBelowTheHeader(t *testing.T) {
	conn, clientQUIC := newDatagramConn(t)
	conn.udpMTU = 10
	destination := M.Socksaddr{Fqdn: "example.com", Port: 53}
	var err error
	withoutPanic(t, "WritePacket", func() {
		err = conn.WritePacket(buf.As([]byte("payload")), destination)
	})
	if err != nil {
		t.Fatal(err)
	}
	message := receiveDatagram(t, clientQUIC)
	if message.destination != destination.String() || string(message.data.Bytes()) != "payload" {
		t.Fatalf("the client received %q for %q", message.data.Bytes(), message.destination)
	}
}

func TestDecodeUDPMessageRefusesAnFQDNLongerThan255(t *testing.T) {
	encode := func(destination string) []byte {
		message := &udpMessage{sessionID: 1, packetID: 1, fragmentTotal: 1, destination: destination, data: buf.As([]byte("payload"))}
		packed := message.pack()
		defer packed.Release()
		return append([]byte(nil), packed.Bytes()...)
	}
	if err := decodeUDPMessage(new(udpMessage), encode(fqdnOfLength(256)+":53")); err == nil || !strings.Contains(err.Error(), "fqdn too long") {
		t.Fatalf("a 256-character destination was decoded: %v", err)
	}
	if err := decodeUDPMessage(new(udpMessage), encode(fqdnOfLength(255)+":53")); err != nil {
		t.Fatalf("a 255-character destination was refused: %v", err)
	}
}

type destinationRecorder struct {
	destinations chan M.Socksaddr
}

func (r *destinationRecorder) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	r.destinations <- destination
}

func (r *destinationRecorder) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
}

func handleTCPRequest(t *testing.T, destination string) (M.Socksaddr, error) {
	t.Helper()
	serverQUIC, clientQUIC := newTestQUICPair(t, &quic.Config{})
	recorder := &destinationRecorder{destinations: make(chan M.Socksaddr, 1)}
	service := &Service[int]{
		ctx:      context.Background(),
		logger:   logger.NOP(),
		handler:  recorder,
		sessions: make(map[*serverSession[int]]struct{}),
	}
	session := &serverSession[int]{
		Service:    service,
		ctx:        service.ctx,
		quicConn:   serverQUIC,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	session.authenticated.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientStream, err := clientQUIC.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.WriteTCPRequest(destination, nil)
	_, err = clientStream.Write(request.Bytes())
	request.Release()
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := serverQUIC.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = quicvarint.Read(quicvarint.NewReader(serverStream)); err != nil {
		t.Fatal(err)
	}
	err = session.handleStream(serverStream)
	select {
	case handled := <-recorder.destinations:
		return handled, err
	default:
		return M.Socksaddr{}, err
	}
}

func TestTCPRequestRefusesAnFQDNLongerThan255(t *testing.T) {
	handled, err := handleTCPRequest(t, fqdnOfLength(256)+":443")
	if err == nil || !strings.Contains(err.Error(), "fqdn too long") || handled.IsValid() {
		t.Fatalf("a 256-character destination was handed to the router as %q: %v", handled.Fqdn, err)
	}
	handled, err = handleTCPRequest(t, fqdnOfLength(255)+":443")
	if err != nil || handled.Fqdn != fqdnOfLength(255) {
		t.Fatalf("a 255-character destination was not handed to the router: %q %v", handled.Fqdn, err)
	}
}
