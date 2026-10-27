package hysteria2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const testQUICProtocol = "hysteria2-test"

func testTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func newTestQUICPair(t *testing.T, config *quic.Config) (*quic.Conn, *quic.Conn) {
	t.Helper()
	certificate, roots := testTLSCertificate(t)
	listener, err := quic.Listen(listenLoopbackUDP(t), &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{testQUICProtocol},
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type acceptResult struct {
		conn *quic.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept(ctx)
		accepted <- acceptResult{conn, acceptErr}
	}()
	client, err := quic.Dial(ctx, listenLoopbackUDP(t), listener.Addr(), &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		NextProtos: []string{testQUICProtocol},
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	t.Cleanup(func() { _ = result.conn.CloseWithError(0, "") })
	return result.conn, client
}

func TestServerConnCloseUnblocksWriteStalledOnFlowControl(t *testing.T) {
	serverQUIC, clientQUIC := newTestQUICPair(t, &quic.Config{
		InitialStreamReceiveWindow: 16 << 10,
		MaxStreamReceiveWindow:     16 << 10,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientStream, err := clientQUIC.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = clientStream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	serverStream, err := serverQUIC.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn := &serverConn{Stream: serverStream}

	writeResult := make(chan error, 1)
	go func() {
		chunk := make([]byte, 32<<10)
		for {
			if _, writeErr := conn.Write(chunk); writeErr != nil {
				writeResult <- writeErr
				return
			}
		}
	}()
	select {
	case writeErr := <-writeResult:
		t.Fatalf("write returned before the peer's flow-control window filled: %v", writeErr)
	case <-time.After(500 * time.Millisecond):
	}

	_ = conn.Close()
	select {
	case <-writeResult:
	case <-time.After(3 * time.Second):
		t.Fatal("a write stalled on flow control was still blocked 3s after serverConn.Close")
	}
}

type recordingPacketHandler struct {
	packetConns chan N.PacketConn
}

func (h *recordingPacketHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
}

func (h *recordingPacketHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.packetConns <- conn
}

func TestServerSessionClosesUDPSessionsWhenConnectionEnds(t *testing.T) {
	serverQUIC, clientQUIC := newTestQUICPair(t, &quic.Config{EnableDatagrams: true})
	handler := &recordingPacketHandler{packetConns: make(chan N.PacketConn, 1)}
	service := &Service[int]{
		ctx:        context.Background(),
		logger:     logger.NOP(),
		udpTimeout: time.Minute,
		handler:    handler,
		sessions:   make(map[*serverSession[int]]struct{}),
	}
	session := &serverSession[int]{
		Service:    service,
		ctx:        service.ctx,
		quicConn:   serverQUIC,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	go session.loopMessages()

	message := &udpMessage{
		sessionID:     7,
		fragmentTotal: 1,
		destination:   "127.0.0.1:53",
		data:          buf.As([]byte("udp payload")),
	}
	packed := message.pack()
	err := clientQUIC.SendDatagram(packed.Bytes())
	packed.Release()
	if err != nil {
		t.Fatal(err)
	}

	var packetConn N.PacketConn
	select {
	case packetConn = <-handler.packetConns:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never opened the UDP session")
	}
	readResult := make(chan error, 1)
	go func() {
		buffer := buf.NewPacket()
		defer buffer.Release()
		for {
			if _, readErr := packetConn.ReadPacket(buffer); readErr != nil {
				readResult <- readErr
				return
			}
			buffer.Reset()
		}
	}()

	_ = clientQUIC.CloseWithError(0, "client gone")
	select {
	case <-readResult:
	case <-time.After(5 * time.Second):
		t.Fatal("the UDP session of a closed connection was still open 5s later; it would linger until udpTimeout")
	}
}

func TestHotReloadRemovingUserClosesTheirUDPSessionsUnderTraffic(t *testing.T) {
	serverQUIC, clientQUIC := newTestQUICPair(t, &quic.Config{EnableDatagrams: true})
	handler := &recordingPacketHandler{packetConns: make(chan N.PacketConn, 1)}
	service := &Service[int]{
		ctx:        context.Background(),
		logger:     logger.NOP(),
		udpTimeout: time.Minute,
		handler:    handler,
		sessions:   make(map[*serverSession[int]]struct{}),
	}
	credentials := []string{"alice-credential", "bob-credential"}
	service.UpdateUsers([]int{1, 2}, credentials)
	session := &serverSession[int]{
		Service:      service,
		ctx:          service.ctx,
		quicConn:     serverQUIC,
		connDone:     make(chan struct{}),
		authUser:     1,
		authPassword: credentials[0],
		udpConnMap:   make(map[uint32]*udpPacketConn),
	}
	session.authenticated.Store(true)
	service.addSession(session)
	defer service.removeSession(session)
	go session.loopMessages()

	stop := make(chan struct{})
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			message := &udpMessage{
				sessionID:     7,
				fragmentTotal: 1,
				destination:   "127.0.0.1:53",
				data:          buf.As([]byte("udp payload")),
			}
			packed := message.pack()
			_ = clientQUIC.SendDatagram(packed.Bytes())
			packed.Release()
			time.Sleep(time.Millisecond)
		}
	}()
	defer func() {
		close(stop)
		<-senderDone
	}()

	var packetConn N.PacketConn
	select {
	case packetConn = <-handler.packetConns:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never opened the UDP session")
	}
	readResult := make(chan error, 1)
	go func() {
		buffer := buf.NewPacket()
		defer buffer.Release()
		for {
			if _, readErr := packetConn.ReadPacket(buffer); readErr != nil {
				readResult <- readErr
				return
			}
			buffer.Reset()
		}
	}()

	time.Sleep(50 * time.Millisecond)
	service.UpdateUsers([]int{2}, credentials[1:])
	select {
	case <-readResult:
	case <-time.After(5 * time.Second):
		t.Fatal("the removed user's UDP session was still open 5s after the hot-reload")
	}
}
