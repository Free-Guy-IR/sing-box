package vless

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
)

var visionCloseTestUUID = [16]byte{0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c}

func visionApplicationDataRecord() []byte {
	return []byte{0x17, 0x03, 0x03, 0x00, 0x04, 'p', 'i', 'n', 'g'}
}

func visionHandshakeRecord() []byte {
	return []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x14, 0x00, 0x00, 0x00}
}

func visionLargeApplicationDataRecord() []byte {
	record := make([]byte, 9000)
	copy(record, visionApplicationDataRecord())
	return record
}

func visionHandshakeThenLargeApplicationData() []byte {
	handshake := make([]byte, 40)
	copy(handshake, []byte{0x16, 0x03, 0x03, 0x00, 35, 0x14})
	return append(handshake, visionLargeApplicationDataRecord()...)
}

func visionTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vision.test"},
		DNSNames:              []string{"vision.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
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

type visionCountingConn struct {
	net.Conn
	read atomic.Int64
}

func (c *visionCountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

type visionTLSPair struct {
	client    *tls.Conn
	server    *tls.Conn
	serverRaw *visionCountingConn
}

func newVisionTLSPair(t *testing.T) visionTLSPair {
	t.Helper()
	return newVisionTLSPairOver(t, func(conn net.Conn) net.Conn { return conn })
}

func newVisionTLSPairOver(t *testing.T, wrapClientRaw func(net.Conn) net.Conn) visionTLSPair {
	t.Helper()
	return newVisionTLSPairOn(t, "tcp", "127.0.0.1:0", wrapClientRaw)
}

func newVisionTLSPairOn(t *testing.T, network string, address string, wrapClientRaw func(net.Conn) net.Conn) visionTLSPair {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptFailed := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptFailed <- acceptErr
			return
		}
		accepted <- conn
	}()
	clientRaw, err := net.Dial(network, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case err = <-acceptFailed:
		clientRaw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clientRaw.Close()
		serverConn.Close()
	})
	deadline := time.Now().Add(20 * time.Second)
	clientRaw.SetDeadline(deadline)
	serverConn.SetDeadline(deadline)
	serverRaw := &visionCountingConn{Conn: serverConn}
	certificate, roots := visionTestCertificate(t)
	server := tls.Server(serverRaw, &tls.Config{
		Certificates:                []tls.Certificate{certificate},
		MinVersion:                  tls.VersionTLS13,
		SessionTicketsDisabled:      true,
		DynamicRecordSizingDisabled: true,
	})
	client := tls.Client(wrapClientRaw(clientRaw), &tls.Config{
		ServerName:                  "vision.test",
		RootCAs:                     roots,
		MinVersion:                  tls.VersionTLS13,
		DynamicRecordSizingDisabled: true,
	})
	serverHandshake := make(chan error, 1)
	go func() {
		serverHandshake <- server.Handshake()
	}()
	if err = client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err = <-serverHandshake; err != nil {
		t.Fatal(err)
	}
	return visionTLSPair{client: client, server: server, serverRaw: serverRaw}
}

func newXTLSVisionConn(conn net.Conn, netConn net.Conn) *VisionConn {
	return &VisionConn{
		Conn:                 conn,
		reader:               bufio.NewChunkReader(conn, xrayChunkSize),
		writer:               bufio.NewVectorisedWriter(conn),
		input:                bytes.NewReader(nil),
		rawInput:             new(bytes.Buffer),
		netConn:              netConn,
		logger:               logger.NOP(),
		userUUID:             visionCloseTestUUID,
		isTLS:                true,
		isTLS12orAbove:       true,
		enableXTLS:           true,
		isPadding:            true,
		writeUUID:            true,
		withinPaddingBuffers: true,
		remainingContent:     -1,
		remainingPadding:     -1,
	}
}

func readVisionDirectFrame(server *tls.Conn) ([]byte, error) {
	header := make([]byte, 21)
	if _, err := io.ReadFull(server, header); err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:16], visionCloseTestUUID[:]) {
		return nil, fmt.Errorf("frame starts with %x, want the user UUID", header[:16])
	}
	if header[16] != commandPaddingDirect {
		return nil, fmt.Errorf("frame command %d, want %d", header[16], commandPaddingDirect)
	}
	contentLen := int(header[17])<<8 | int(header[18])
	paddingLen := int(header[19])<<8 | int(header[20])
	body := make([]byte, contentLen+paddingLen)
	if _, err := io.ReadFull(server, body); err != nil {
		return nil, err
	}
	return body[:contentLen], nil
}

type visionReadResult struct {
	data []byte
	err  error
}

func readVisionPeerContent(conn *VisionConn) ([]byte, error) {
	content := make([]byte, 64)
	n, err := conn.Read(content)
	return content[:n], err
}

func TestVisionCloseAfterDirectWriteSendsNothingOnTheRawConn(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		peerDirectsUs bool
	}{
		{name: "with the peer still padding"},
		{name: "after the peer's direct frame", peerDirectsUs: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			pair := newVisionTLSPair(t)
			conn := newXTLSVisionConn(pair.client, pair.client.NetConn())
			if testCase.peerDirectsUs {
				if _, err := pair.server.Write(visionTestFrame(true, commandPaddingDirect, visionApplicationDataRecord(), 10)); err != nil {
					t.Fatal(err)
				}
				content, err := readVisionPeerContent(conn)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(content, visionApplicationDataRecord()) || !conn.directRead {
					t.Fatalf("read %x directRead=%v from the peer's direct frame", content, conn.directRead)
				}
			}
			frame := make(chan visionReadResult, 1)
			rest := make(chan visionReadResult, 1)
			go func() {
				content, err := readVisionDirectFrame(pair.server)
				frame <- visionReadResult{content, err}
				if err != nil {
					return
				}
				data, err := io.ReadAll(pair.serverRaw)
				rest <- visionReadResult{data, err}
			}()
			record := visionApplicationDataRecord()
			if _, err := conn.Write(record); err != nil {
				t.Fatal(err)
			}
			received := <-frame
			if received.err != nil {
				t.Fatal(received.err)
			}
			if !bytes.Equal(received.data, record) {
				t.Fatalf("direct frame carried %x, want %x", received.data, record)
			}
			rawPayload := []byte("raw-after-direct")
			if _, err := conn.Write(rawPayload); err != nil {
				t.Fatal(err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			received = <-rest
			if received.err != nil {
				t.Fatal(received.err)
			}
			if !bytes.Equal(received.data, rawPayload) {
				t.Fatalf("raw conn carried %x after the direct switch, want only %x", received.data, rawPayload)
			}
			if _, err := pair.client.NetConn().Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("client raw conn read returned %v after Close, want net.ErrClosed", err)
			}
		})
	}
}

func TestVisionCloseBeforeDirectWriteSendsCloseNotify(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		peerCommand byte
		peerContent []byte
	}{
		{name: "before any peer frame"},
		{name: "after the peer's padded frame", peerCommand: commandPaddingContinue, peerContent: visionHandshakeRecord()},
		{name: "after the peer's direct frame", peerCommand: commandPaddingDirect, peerContent: visionApplicationDataRecord()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			pair := newVisionTLSPair(t)
			conn := newXTLSVisionConn(pair.client, pair.client.NetConn())
			if testCase.peerContent != nil {
				if _, err := pair.server.Write(visionTestFrame(true, testCase.peerCommand, testCase.peerContent, 10)); err != nil {
					t.Fatal(err)
				}
				content, err := readVisionPeerContent(conn)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(content, testCase.peerContent) {
					t.Fatalf("read %x from the peer frame, want %x", content, testCase.peerContent)
				}
			}
			readBeforeClose := pair.serverRaw.read.Load()
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			n, err := pair.server.Read(make([]byte, 1))
			if n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("server read n=%d err=%v, want io.EOF", n, err)
			}
			if pair.serverRaw.read.Load() == readBeforeClose {
				t.Fatal("server reached io.EOF on a bare FIN, want a close_notify record first")
			}
			if err = pair.client.NetConn().SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("client raw conn SetDeadline returned %v after Close, want net.ErrClosed", err)
			}
			if rest, err := io.ReadAll(pair.serverRaw); err != nil || len(rest) != 0 {
				t.Fatalf("server raw conn read %x and %v after the close_notify, want a clean end of stream", rest, err)
			}
		})
	}
}

type visionCloseRecorder struct {
	closed      atomic.Int32
	written     atomic.Int64
	closeErr    error
	readData    []byte
	maxRead     int
	wrote       []byte
	blockWrite  bool
	blocked     chan struct{}
	blockedOnce sync.Once
	release     chan struct{}
	onWrite     func([]byte)
	halfClosed  atomic.Int32
	closeOnce   sync.Once
	done        chan struct{}
}

func (c *visionCloseRecorder) Read(p []byte) (int, error) {
	if len(c.readData) == 0 {
		return 0, io.EOF
	}
	if c.maxRead > 0 && len(p) > c.maxRead {
		p = p[:c.maxRead]
	}
	n := copy(p, c.readData)
	c.readData = c.readData[n:]
	return n, nil
}

func (c *visionCloseRecorder) Write(p []byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite(p)
	}
	if c.blockWrite {
		c.blockedOnce.Do(func() { close(c.blocked) })
		if c.release != nil {
			<-c.release
		} else {
			<-c.done
		}
		return 0, net.ErrClosed
	}
	c.written.Add(int64(len(p)))
	c.wrote = append(c.wrote, p...)
	return len(p), nil
}

func (c *visionCloseRecorder) Close() error {
	c.closed.Add(1)
	c.closeOnce.Do(func() { close(c.done) })
	return c.closeErr
}
func (c *visionCloseRecorder) CloseWrite() error {
	c.halfClosed.Add(1)
	return nil
}
func (c *visionCloseRecorder) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *visionCloseRecorder) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *visionCloseRecorder) SetDeadline(t time.Time) error      { return nil }
func (c *visionCloseRecorder) SetReadDeadline(t time.Time) error  { return nil }
func (c *visionCloseRecorder) SetWriteDeadline(t time.Time) error { return nil }

var (
	errVisionTLSSideClosed = errors.New("tls side closed")
	errVisionRawSideClosed = errors.New("raw side closed")
)

func newRecordedVisionConn() (*VisionConn, *visionCloseRecorder, *visionCloseRecorder) {
	tlsSide := &visionCloseRecorder{closeErr: errVisionTLSSideClosed, done: make(chan struct{})}
	rawSide := &visionCloseRecorder{closeErr: errVisionRawSideClosed, done: make(chan struct{})}
	return newXTLSVisionConn(tlsSide, rawSide), tlsSide, rawSide
}

func visionPeerFrame(command byte) []byte {
	builder := &VisionConn{logger: logger.NOP(), userUUID: visionCloseTestUUID, writeUUID: true, isTLS: true}
	frame := builder.padding(buf.As(visionApplicationDataRecord()), command)
	return frame.Bytes()
}

func TestVisionCloseFollowsTheDirectWrite(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		notTLS      bool
		enableXTLS  bool
		peerFrame   []byte
		write       []byte
		wantPadding bool
		wantTLS     int32
		wantRaw     int32
		wantErr     error
	}{
		{name: "after a direct write", enableXTLS: true, write: visionApplicationDataRecord(), wantTLS: 0, wantRaw: 1, wantErr: errVisionRawSideClosed},
		{name: "after a direct write and a read of the peer's direct frame", enableXTLS: true, peerFrame: visionPeerFrame(commandPaddingDirect), write: visionApplicationDataRecord(), wantTLS: 0, wantRaw: 1, wantErr: errVisionRawSideClosed},
		{name: "before any write", enableXTLS: true, wantPadding: true, wantTLS: 1, wantRaw: 0, wantErr: errVisionTLSSideClosed},
		{name: "after a padded handshake write", enableXTLS: true, write: visionHandshakeRecord(), wantPadding: true, wantTLS: 1, wantRaw: 0, wantErr: errVisionTLSSideClosed},
		{name: "after padding ended without a direct switch", enableXTLS: false, write: visionApplicationDataRecord(), wantTLS: 1, wantRaw: 0, wantErr: errVisionTLSSideClosed},
		{name: "after a read of the peer's direct frame only", enableXTLS: true, peerFrame: visionPeerFrame(commandPaddingDirect), wantPadding: true, wantTLS: 1, wantRaw: 0, wantErr: errVisionTLSSideClosed},
		{name: "after a read of the peer's padding end", enableXTLS: true, peerFrame: visionPeerFrame(commandPaddingEnd), wantPadding: true, wantTLS: 1, wantRaw: 0, wantErr: errVisionTLSSideClosed},
		{name: "with no inner TLS", notTLS: true, wantPadding: true, wantTLS: 1, wantRaw: 0, wantErr: errVisionTLSSideClosed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn, tlsSide, rawSide := newRecordedVisionConn()
			conn.isTLS = !testCase.notTLS
			conn.isTLS12orAbove = !testCase.notTLS
			conn.enableXTLS = testCase.enableXTLS
			if testCase.peerFrame != nil {
				tlsSide.readData = testCase.peerFrame
				content := make([]byte, 64)
				n, err := conn.Read(content)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(content[:n], visionApplicationDataRecord()) {
					t.Fatalf("read %x from the peer frame, want %x", content[:n], visionApplicationDataRecord())
				}
				if conn.withinPaddingBuffers {
					t.Fatal("the peer frame did not end the padding")
				}
			}
			if testCase.write != nil {
				if _, err := conn.Write(testCase.write); err != nil {
					t.Fatal(err)
				}
			}
			if conn.isPadding != testCase.wantPadding {
				t.Fatalf("isPadding %v after the write, want %v", conn.isPadding, testCase.wantPadding)
			}
			if err := conn.Close(); !errors.Is(err, testCase.wantErr) {
				t.Fatalf("Close returned %v, want %v", err, testCase.wantErr)
			}
			if tlsSide.closed.Load() != testCase.wantTLS || rawSide.closed.Load() != testCase.wantRaw {
				t.Fatalf("Close closed tls=%d raw=%d, want tls=%d raw=%d", tlsSide.closed.Load(), rawSide.closed.Load(), testCase.wantTLS, testCase.wantRaw)
			}
			if err := conn.Close(); !errors.Is(err, testCase.wantErr) {
				t.Fatalf("the second Close returned %v, want %v", err, testCase.wantErr)
			}
			if tlsSide.closed.Load() != 2*testCase.wantTLS || rawSide.closed.Load() != 2*testCase.wantRaw {
				t.Fatalf("two Close calls closed tls=%d raw=%d, want tls=%d raw=%d", tlsSide.closed.Load(), rawSide.closed.Load(), 2*testCase.wantTLS, 2*testCase.wantRaw)
			}
		})
	}
}

func TestVisionCloseRacingTheDirectWrite(t *testing.T) {
	for i := 0; i < 500; i++ {
		conn, tlsSide, rawSide := newRecordedVisionConn()
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			conn.Write(visionApplicationDataRecord())
		}()
		go func() {
			defer wg.Done()
			<-start
			conn.Close()
		}()
		close(start)
		wg.Wait()
		if total := tlsSide.closed.Load() + rawSide.closed.Load(); total != 1 {
			t.Fatalf("iteration %d: Close closed tls=%d raw=%d, want exactly one side", i, tlsSide.closed.Load(), rawSide.closed.Load())
		}
	}
}

func TestVisionCloseDoesNotWaitForABlockedDirectWrite(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		heldByTheRaw bool
	}{
		{name: "released by the close"},
		{name: "held past the close", heldByTheRaw: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn, _, rawSide := newRecordedVisionConn()
			if _, err := conn.Write(visionApplicationDataRecord()); err != nil {
				t.Fatal(err)
			}
			rawSide.blockWrite = true
			rawSide.blocked = make(chan struct{})
			var releaseOnce sync.Once
			releaseHeldWrite := func() {}
			if testCase.heldByTheRaw {
				rawSide.release = make(chan struct{})
				releaseHeldWrite = func() { releaseOnce.Do(func() { close(rawSide.release) }) }
			}
			t.Cleanup(func() {
				releaseHeldWrite()
				rawSide.Close()
			})
			writeDone := make(chan error, 1)
			go func() {
				_, err := conn.Write([]byte("blocked-on-the-raw-conn"))
				writeDone <- err
			}()
			select {
			case <-rawSide.blocked:
			case err := <-writeDone:
				t.Fatalf("Write returned %v before blocking on the raw conn", err)
			case <-time.After(5 * time.Second):
				t.Fatal("Write never reached the raw conn")
			}
			closeDone := make(chan error, 1)
			go func() {
				closeDone <- conn.Close()
			}()
			select {
			case err := <-closeDone:
				if !errors.Is(err, errVisionRawSideClosed) {
					t.Fatalf("Close returned %v, want %v", err, errVisionRawSideClosed)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close waited for a Write blocked on the raw conn")
			}
			if testCase.heldByTheRaw {
				select {
				case err := <-writeDone:
					t.Fatalf("the held Write returned %v before its release", err)
				default:
				}
				releaseHeldWrite()
			}
			select {
			case err := <-writeDone:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("blocked Write returned %v, want net.ErrClosed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the blocked Write never returned")
			}
		})
	}
}

func TestVisionCloseDuringTheTrailingDirectWrite(t *testing.T) {
	conn, _, rawSide := newRecordedVisionConn()
	rawSide.blockWrite = true
	rawSide.blocked = make(chan struct{})
	t.Cleanup(func() { rawSide.Close() })
	record := make([]byte, 9000)
	copy(record, visionApplicationDataRecord())
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(record)
		writeDone <- err
	}()
	select {
	case <-rawSide.blocked:
	case err := <-writeDone:
		t.Fatalf("Write returned %v before the trailing buffer reached the raw conn", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the trailing buffer never reached the raw conn")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- conn.Close()
	}()
	select {
	case err := <-closeDone:
		if !errors.Is(err, errVisionRawSideClosed) {
			t.Fatalf("Close returned %v during the trailing direct write, want %v", err, errVisionRawSideClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for the trailing direct write")
	}
	select {
	case err := <-writeDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("trailing Write returned %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not release the trailing Write")
	}
}

func TestVisionCloseDuringTheSwitchingFrameWrite(t *testing.T) {
	inThePeerPadding := len(visionCloseTestUUID) + 5 + len(visionApplicationDataRecord()) + 10
	for _, testCase := range []struct {
		name      string
		peerFrame []byte
		write     []byte
		reached   func(conn *VisionConn) bool
	}{
		{name: "with the peer still padding", write: visionApplicationDataRecord()},
		{name: "after the peer's padded frame", peerFrame: visionPeerFrame(commandPaddingContinue), write: visionApplicationDataRecord()},
		{name: "after the peer's direct frame", peerFrame: visionPeerFrame(commandPaddingDirect), write: visionApplicationDataRecord()},
		{name: "with a handshake record ahead of the switching record", write: visionHandshakeThenLargeApplicationData()},
		{name: "with a split peer padding header", peerFrame: append(visionPeerFrame(commandPaddingContinue), commandPaddingContinue, 0x00, 0x09), write: visionApplicationDataRecord(), reached: func(conn *VisionConn) bool {
			return conn.paddingHeaderLen > 0
		}},
		{name: "after the peer's padding end frame", peerFrame: visionPeerFrame(commandPaddingEnd), write: visionApplicationDataRecord(), reached: func(conn *VisionConn) bool {
			return conn.currentCommand == commandPaddingEnd && !conn.withinPaddingBuffers
		}},
		{name: "in the middle of the peer's padding", peerFrame: visionPeerFrame(commandPaddingContinue)[:inThePeerPadding], write: visionApplicationDataRecord(), reached: func(conn *VisionConn) bool {
			return conn.withinPaddingBuffers && conn.remainingContent == 0 && conn.remainingPadding > 0
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn, tlsSide, _ := newRecordedVisionConn()
			if testCase.peerFrame != nil {
				tlsSide.readData = testCase.peerFrame
				if _, err := readVisionPeerContent(conn); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.reached != nil && !testCase.reached(conn) {
				t.Fatalf("the peer frame left currentCommand=%d withinPaddingBuffers=%v remainingContent=%d remainingPadding=%d paddingHeaderLen=%d, not the state under test", conn.currentCommand, conn.withinPaddingBuffers, conn.remainingContent, conn.remainingPadding, conn.paddingHeaderLen)
			}
			var closeErr error
			var closeCalled bool
			tlsSide.onWrite = func([]byte) {
				if !closeCalled {
					closeCalled = true
					closeErr = conn.Close()
				}
			}
			writeDone := make(chan error, 1)
			go func() {
				_, err := conn.Write(testCase.write)
				writeDone <- err
			}()
			select {
			case <-writeDone:
			case <-time.After(5 * time.Second):
				t.Fatal("Close from inside the switching frame write did not return")
			}
			if !closeCalled {
				t.Fatal("the switching frame never reached the TLS conn")
			}
			if !errors.Is(closeErr, errVisionRawSideClosed) {
				t.Fatalf("Close during the switching frame write returned %v, want %v", closeErr, errVisionRawSideClosed)
			}
		})
	}
}

func TestVisionWriteAndCloseAfterThePaddingEndedStayOnTheTLSConn(t *testing.T) {
	conn, tlsSide, rawSide := newRecordedVisionConn()
	conn.enableXTLS = false
	if _, err := conn.Write(visionApplicationDataRecord()); err != nil {
		t.Fatal(err)
	}
	if conn.isPadding {
		t.Fatal("the write did not end the padding")
	}
	conn.enableXTLS = true
	writtenBefore := tlsSide.written.Load()
	payload := []byte("after-the-padding")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if got := tlsSide.written.Load() - writtenBefore; got != int64(len(payload)) || rawSide.written.Load() != 0 {
		t.Fatalf("write after the padding put %d bytes on tls and %d on raw, want %d on tls only", got, rawSide.written.Load(), len(payload))
	}
	if err := conn.Close(); !errors.Is(err, errVisionTLSSideClosed) {
		t.Fatalf("Close returned %v, want %v", err, errVisionTLSSideClosed)
	}
	if tlsSide.closed.Load() != 1 || rawSide.closed.Load() != 0 {
		t.Fatalf("Close closed tls=%d raw=%d, want tls=1 raw=0", tlsSide.closed.Load(), rawSide.closed.Load())
	}
}

func TestVisionCloseDoesNotWaitForAWriteBlockedOnTheTLSConn(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		endPadding   bool
		heldByTheTLS bool
		blockedWrite []byte
	}{
		{name: "a padded write released by the close", blockedWrite: visionHandshakeRecord()},
		{name: "a padded write held past the close", heldByTheTLS: true, blockedWrite: visionHandshakeRecord()},
		{name: "a write after the padding ended released by the close", endPadding: true, blockedWrite: []byte("after-the-padding")},
		{name: "a write after the padding ended held past the close", endPadding: true, heldByTheTLS: true, blockedWrite: []byte("after-the-padding")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn, tlsSide, rawSide := newRecordedVisionConn()
			if testCase.endPadding {
				conn.enableXTLS = false
				if _, err := conn.Write(visionApplicationDataRecord()); err != nil {
					t.Fatal(err)
				}
				if conn.isPadding {
					t.Fatal("the write did not end the padding")
				}
			}
			tlsSide.blockWrite = true
			tlsSide.blocked = make(chan struct{})
			var releaseOnce sync.Once
			releaseHeldWrite := func() {}
			if testCase.heldByTheTLS {
				tlsSide.release = make(chan struct{})
				releaseHeldWrite = func() { releaseOnce.Do(func() { close(tlsSide.release) }) }
			}
			t.Cleanup(func() {
				releaseHeldWrite()
				tlsSide.Close()
			})
			writeDone := make(chan error, 1)
			go func() {
				_, err := conn.Write(testCase.blockedWrite)
				writeDone <- err
			}()
			select {
			case <-tlsSide.blocked:
			case err := <-writeDone:
				t.Fatalf("Write returned %v before blocking on the TLS conn", err)
			case <-time.After(5 * time.Second):
				t.Fatal("Write never reached the TLS conn")
			}
			closeDone := make(chan error, 1)
			go func() {
				closeDone <- conn.Close()
			}()
			select {
			case err := <-closeDone:
				if !errors.Is(err, errVisionTLSSideClosed) {
					t.Fatalf("Close returned %v, want %v", err, errVisionTLSSideClosed)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close waited for a Write blocked on the TLS conn")
			}
			if rawSide.closed.Load() != 0 {
				t.Fatal("Close closed the raw conn without a direct write")
			}
			if testCase.heldByTheTLS {
				select {
				case err := <-writeDone:
					t.Fatalf("the held Write returned %v before its release", err)
				default:
				}
				releaseHeldWrite()
			}
			select {
			case err := <-writeDone:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("blocked Write returned %v, want net.ErrClosed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the blocked Write never returned")
			}
		})
	}
}

func visionClientHelloRecord() []byte {
	return []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}
}

func visionServerHelloRecord(cipher uint16, tls13 bool) []byte {
	record := make([]byte, 200)
	copy(record, []byte{0x16, 0x03, 0x03, 0x00, 195, 0x02})
	record[44] = byte(cipher >> 8)
	record[45] = byte(cipher)
	if tls13 {
		copy(record[50:], tls13SupportedVersions)
	}
	return record
}

func visionTestFrame(withUUID bool, command byte, content []byte, paddingLen int) []byte {
	var frame []byte
	if withUUID {
		frame = append(frame, visionCloseTestUUID[:]...)
	}
	frame = append(frame, command, byte(len(content)>>8), byte(len(content)), byte(paddingLen>>8), byte(paddingLen))
	frame = append(frame, content...)
	return append(frame, make([]byte, paddingLen)...)
}

func newFreshVisionConn(conn net.Conn, netConn net.Conn) *VisionConn {
	return &VisionConn{
		Conn:     conn,
		reader:   bufio.NewChunkReader(conn, xrayChunkSize),
		writer:   bufio.NewVectorisedWriter(conn),
		input:    bytes.NewReader(nil),
		rawInput: new(bytes.Buffer),
		netConn:  netConn,
		logger:   logger.NOP(),

		userUUID:               visionCloseTestUUID,
		numberOfPacketToFilter: 8,
		remainingServerHello:   -1,
		isPadding:              true,
		writeUUID:              true,
		withinPaddingBuffers:   true,
		remainingContent:       -1,
		remainingPadding:       -1,
	}
}

func visionWroteADirectFrame(stream []byte) (bool, error) {
	if len(stream) == 0 {
		return false, nil
	}
	if len(stream) < 16 || !bytes.Equal(stream[:16], visionCloseTestUUID[:]) {
		return false, fmt.Errorf("the TLS side starts with %x, want the user UUID", stream)
	}
	stream = stream[16:]
	for len(stream) > 0 {
		if len(stream) < 5 {
			return false, fmt.Errorf("a short padding header %x", stream)
		}
		command := stream[0]
		frameLen := 5 + (int(stream[1])<<8 | int(stream[2])) + (int(stream[3])<<8 | int(stream[4]))
		if len(stream) < frameLen {
			return false, fmt.Errorf("a frame of %d bytes with %d written", frameLen, len(stream))
		}
		switch command {
		case commandPaddingDirect:
			return true, nil
		case commandPaddingEnd:
			return false, nil
		}
		stream = stream[frameLen:]
	}
	return false, nil
}

func TestVisionCloseFollowsTheWrittenDirectFrame(t *testing.T) {
	random := mathrand.New(mathrand.NewSource(20261103))
	randomBytes := func(n int) []byte {
		data := make([]byte, n)
		random.Read(data)
		return data
	}
	readLimit := func() int {
		if random.Intn(2) == 0 {
			return 0
		}
		return 21 + random.Intn(180)
	}
	largeRecord := visionLargeApplicationDataRecord()
	mixedRecord := visionHandshakeThenLargeApplicationData()
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0x1304, 0x1305}
	coverage := map[string]int{}
	var releaseHeld func()
	t.Cleanup(func() {
		if releaseHeld != nil {
			releaseHeld()
		}
	})
	for iteration := 0; iteration < 10000; iteration++ {
		tlsSide := &visionCloseRecorder{closeErr: errVisionTLSSideClosed, done: make(chan struct{}), maxRead: readLimit()}
		rawSide := &visionCloseRecorder{closeErr: errVisionRawSideClosed, done: make(chan struct{}), maxRead: readLimit()}
		conn := newFreshVisionConn(tlsSide, rawSide)
		steps := []string{fmt.Sprintf("read limits tls=%d raw=%d", tlsSide.maxRead, rawSide.maxRead)}
		if random.Intn(2) == 0 {
			conn.input = bytes.NewReader(randomBytes(1 + random.Intn(40)))
			conn.rawInput = bytes.NewBuffer(randomBytes(1 + random.Intn(40)))
			steps = append(steps, fmt.Sprintf("tls holds %d unread and %d raw bytes", conn.input.Len(), conn.rawInput.Len()))
		}
		peerFrames := 0
		peerCommand := commandPaddingContinue
		var peerPending []byte
		sendPeerFrame := func(command byte, content []byte) {
			frame := visionTestFrame(peerFrames == 0, command, content, random.Intn(1400))
			tlsSide.readData = append(tlsSide.readData, peerPending...)
			peerPending = nil
			split := len(frame)
			if random.Intn(3) == 0 {
				minimumSplit := 1
				if peerFrames == 0 {
					minimumSplit = 21
				}
				split = minimumSplit + random.Intn(len(frame)-minimumSplit)
				if peerFrames > 0 && random.Intn(2) == 0 {
					split = 1 + random.Intn(4)
				}
				peerPending = frame[split:]
			}
			tlsSide.readData = append(tlsSide.readData, frame[:split]...)
			steps = append(steps, fmt.Sprintf("peer sends frame %d command %d of %d bytes, %d now", peerFrames, command, len(frame), split))
			peerFrames++
		}
		for step := random.Intn(15); step > 0; step-- {
			var err error
			switch random.Intn(8) {
			case 7:
				steps = append(steps, "write a handshake record and a large application data record at once")
				_, err = conn.Write(mixedRecord)
			case 0:
				steps = append(steps, "write a client hello")
				_, err = conn.Write(visionClientHelloRecord())
			case 1:
				steps = append(steps, "write a handshake record")
				_, err = conn.Write(visionHandshakeRecord())
			case 2:
				steps = append(steps, "write an application data record")
				_, err = conn.Write(visionApplicationDataRecord())
			case 3:
				steps = append(steps, "write a large application data record")
				_, err = conn.Write(largeRecord)
			case 4, 5:
				switch peerCommand {
				case commandPaddingContinue:
					switch random.Intn(4) {
					case 0, 3:
						cipher := ciphers[random.Intn(len(ciphers))]
						tls13 := random.Intn(5) != 0
						steps = append(steps, fmt.Sprintf("server hello cipher %#x tls13 %v", cipher, tls13))
						sendPeerFrame(commandPaddingContinue, visionServerHelloRecord(cipher, tls13))
					case 1:
						sendPeerFrame(commandPaddingDirect, visionApplicationDataRecord())
						peerCommand = commandPaddingDirect
					case 2:
						sendPeerFrame(commandPaddingEnd, visionApplicationDataRecord())
						peerCommand = commandPaddingEnd
					}
				case commandPaddingDirect:
					steps = append(steps, "peer sends raw bytes")
					tlsSide.readData = append(tlsSide.readData, peerPending...)
					peerPending = nil
					rawSide.readData = append(rawSide.readData, visionApplicationDataRecord()...)
				case commandPaddingEnd:
					steps = append(steps, "peer sends plain bytes")
					tlsSide.readData = append(tlsSide.readData, peerPending...)
					peerPending = nil
					tlsSide.readData = append(tlsSide.readData, visionApplicationDataRecord()...)
				}
			case 6:
				pending := len(conn.remainingBuffers) > 0 || len(tlsSide.readData) > 0
				if conn.directRead {
					pending = len(conn.remainingBuffers) > 0 || len(rawSide.readData) > 0
				}
				if !pending {
					continue
				}
				readSize := 1 + random.Intn(64)
				steps = append(steps, fmt.Sprintf("read %d bytes", readSize))
				_, err = conn.Read(make([]byte, readSize))
				if errors.Is(err, io.EOF) {
					err = nil
				}
			}
			if err != nil {
				t.Fatalf("iteration %d after %v: %v", iteration, steps, err)
			}
		}
		wantRaw, err := visionWroteADirectFrame(tlsSide.wrote)
		if err != nil {
			t.Fatalf("iteration %d after %v: %v", iteration, steps, err)
		}
		closeMode := random.Intn(3)
		blockAWrite := closeMode == 1
		if closeMode == 2 {
			steps = append(steps, "close inside the next write")
			var insideCalled, insideWantRaw bool
			var insideParseErr, insideErr error
			tlsSide.onWrite = func(p []byte) {
				if insideCalled {
					return
				}
				insideCalled = true
				insideWantRaw, insideParseErr = visionWroteADirectFrame(append(append([]byte(nil), tlsSide.wrote...), p...))
				insideErr = conn.Close()
			}
			record := [][]byte{visionApplicationDataRecord(), largeRecord, mixedRecord}[random.Intn(3)]
			writeDone := make(chan error, 1)
			go func() {
				_, writeErr := conn.Write(record)
				writeDone <- writeErr
			}()
			select {
			case <-writeDone:
			case <-time.After(5 * time.Second):
				t.Fatalf("iteration %d after %v: Close inside a write did not return", iteration, steps)
			}
			tlsSide.onWrite = nil
			if insideCalled {
				if insideParseErr != nil {
					t.Fatalf("iteration %d after %v: %v", iteration, steps, insideParseErr)
				}
				wantErr, wantTLS, wantRawClosed := errVisionTLSSideClosed, int32(1), int32(0)
				if insideWantRaw {
					wantErr, wantTLS, wantRawClosed = errVisionRawSideClosed, 0, 1
					coverage["close inside a switching write"]++
					if len(record) == len(mixedRecord) {
						coverage["close inside a switching write with a handshake record ahead"]++
					}
					if conn.directRead {
						coverage["close inside a switching write after the peer's direct frame"]++
					}
				}
				if !errors.Is(insideErr, wantErr) {
					t.Fatalf("iteration %d after %v: Close inside the write returned %v, want %v", iteration, steps, insideErr, wantErr)
				}
				if tlsSide.closed.Load() != wantTLS || rawSide.closed.Load() != wantRawClosed || tlsSide.halfClosed.Load()+rawSide.halfClosed.Load() != 0 {
					t.Fatalf("iteration %d after %v: Close inside the write closed tls=%d raw=%d half=%d, want tls=%d raw=%d", iteration, steps, tlsSide.closed.Load(), rawSide.closed.Load(), tlsSide.halfClosed.Load()+rawSide.halfClosed.Load(), wantTLS, wantRawClosed)
				}
				continue
			}
			if wantRaw, err = visionWroteADirectFrame(tlsSide.wrote); err != nil {
				t.Fatalf("iteration %d after %v: %v", iteration, steps, err)
			}
		}
		if wantRaw && conn.remainingServerHello > 0 {
			coverage["direct with a partly read server hello"]++
		}
		if wantRaw && conn.withinPaddingBuffers && conn.remainingContent > 0 {
			coverage["direct in the middle of peer content"]++
		}
		if wantRaw && (conn.input.Len() > 0 || conn.rawInput.Len() > 0) {
			coverage["direct with unread TLS input"]++
		}
		if !wantRaw && conn.enableXTLS {
			coverage["XTLS without a direct frame"]++
		}
		if !wantRaw && conn.cipher == 0x1305 {
			coverage["CCM_8 server hello"]++
		}
		if wantRaw {
			coverage["direct"]++
		}
		if len(conn.remainingBuffers) > 0 {
			coverage["buffered read data"]++
		}
		if conn.paddingHeaderLen > 0 {
			coverage["split padding header"]++
		}
		if blockAWrite && wantRaw && conn.directRead {
			coverage["blocked raw write after the peer's direct frame"]++
		}
		if blockAWrite && !wantRaw && conn.remainingContent != -1 {
			coverage["blocked TLS write after a peer frame"]++
		}
		wantErr, wantTLS, wantRawClosed := errVisionTLSSideClosed, int32(1), int32(0)
		blockedSide := tlsSide
		if wantRaw {
			wantErr, wantTLS, wantRawClosed = errVisionRawSideClosed, 0, 1
			blockedSide = rawSide
		}
		var writeDone chan error
		if blockAWrite {
			steps = append(steps, "block a handshake record write")
			blockedSide.blockWrite = true
			blockedSide.blocked = make(chan struct{})
			blockedSide.release = make(chan struct{})
			var releaseOnce sync.Once
			release := blockedSide.release
			releaseHeld = func() { releaseOnce.Do(func() { close(release) }) }
			writeDone = make(chan error, 1)
			go func() {
				_, writeErr := conn.Write(visionHandshakeRecord())
				writeDone <- writeErr
			}()
			select {
			case <-blockedSide.blocked:
			case err = <-writeDone:
				t.Fatalf("iteration %d after %v: the write returned %v before blocking", iteration, steps, err)
			case <-time.After(5 * time.Second):
				t.Fatalf("iteration %d after %v: the write never reached the expected conn", iteration, steps)
			}
		}
		closeDone := make(chan error, 1)
		go func() {
			closeDone <- conn.Close()
		}()
		select {
		case err = <-closeDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d after %v: Close waited", iteration, steps)
		}
		if !errors.Is(err, wantErr) {
			t.Fatalf("iteration %d after %v: Close returned %v, want %v", iteration, steps, err, wantErr)
		}
		if tlsSide.closed.Load() != wantTLS || rawSide.closed.Load() != wantRawClosed || tlsSide.halfClosed.Load()+rawSide.halfClosed.Load() != 0 {
			t.Fatalf("iteration %d after %v: Close closed tls=%d raw=%d half=%d, want tls=%d raw=%d", iteration, steps, tlsSide.closed.Load(), rawSide.closed.Load(), tlsSide.halfClosed.Load()+rawSide.halfClosed.Load(), wantTLS, wantRawClosed)
		}
		if blockAWrite {
			releaseHeld()
			select {
			case <-writeDone:
			case <-time.After(5 * time.Second):
				t.Fatalf("iteration %d after %v: the released write never returned", iteration, steps)
			}
		}
	}
	t.Logf("coverage %v", coverage)
	for _, name := range []string{
		"direct",
		"direct with a partly read server hello",
		"direct in the middle of peer content",
		"direct with unread TLS input",
		"XTLS without a direct frame",
		"CCM_8 server hello",
		"buffered read data",
		"split padding header",
		"blocked raw write after the peer's direct frame",
		"blocked TLS write after a peer frame",
		"close inside a switching write",
		"close inside a switching write after the peer's direct frame",
		"close inside a switching write with a handshake record ahead",
	} {
		if coverage[name] == 0 {
			t.Fatalf("the generated states never reached %q: %v", name, coverage)
		}
	}
}

type visionPlaintextRecorder struct {
	*tls.Conn
	wrote        []byte
	stopRecord   bool
	writingSince atomic.Int64
}

func (c *visionPlaintextRecorder) Write(p []byte) (int, error) {
	if !c.stopRecord {
		c.wrote = append(c.wrote, p...)
	}
	c.writingSince.Store(time.Now().UnixNano())
	defer c.writingSince.Store(0)
	return c.Conn.Write(p)
}

type visionRawWriteWatch struct {
	net.Conn
	writingSince atomic.Int64
}

func (c *visionRawWriteWatch) Write(p []byte) (int, error) {
	c.writingSince.Store(time.Now().UnixNano())
	defer c.writingSince.Store(0)
	return c.Conn.Write(p)
}

func waitForAStuckWrite(writeDone chan error, stuckFor time.Duration, writingSince ...*atomic.Int64) (int, error) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-writeDone:
			return -1, fmt.Errorf("the writes to a peer that reads nothing ended with %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		for index, since := range writingSince {
			if started := since.Load(); started != 0 && time.Since(time.Unix(0, started)) > stuckFor {
				return index, nil
			}
		}
	}
	return -1, errors.New("no write got stuck on the conn")
}

func (c *visionPlaintextRecorder) ReaderReplaceable() bool { return true }

func (c *visionPlaintextRecorder) Upstream() any { return c.Conn }

func readVisionPeerContentWithin(conn *VisionConn, size int, timeout time.Duration) (int, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	return conn.Read(make([]byte, size))
}

type visionDriveOptions struct {
	handshakeOnly      bool
	mayEndOnPeerFrame  bool
	startWithXTLSHello bool
}

func driveVisionRealConn(random *mathrand.Rand, pair visionTLSPair, conn *VisionConn, options visionDriveOptions) ([]string, error) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0x1304, 0x1305}
	var steps []string
	if random.Intn(3) == 0 {
		conn.input = bytes.NewReader(make([]byte, 1+random.Intn(40)))
		conn.rawInput = bytes.NewBuffer(make([]byte, 1+random.Intn(40)))
		steps = append(steps, "tls holds unread input")
	}
	peerFrames := 0
	peerCommand := commandPaddingContinue
	peerStalled := false
	unread := 0
	readSome := func(all bool) error {
		for unread > 0 {
			n, err := readVisionPeerContentWithin(conn, 1+random.Intn(64), 5*time.Second)
			unread -= n
			if err != nil {
				return err
			}
			if !all {
				return nil
			}
		}
		return nil
	}
	if options.startWithXTLSHello {
		cipher := ciphers[random.Intn(4)]
		steps = append(steps, fmt.Sprintf("peer sends a TLS 1.3 server hello cipher %#x first", cipher))
		content := visionServerHelloRecord(cipher, true)
		if _, err := pair.server.Write(visionTestFrame(true, commandPaddingContinue, content, random.Intn(1400))); err != nil {
			return steps, err
		}
		peerFrames++
		unread += len(content)
		if err := readSome(true); err != nil {
			return steps, err
		}
	}
	for step := random.Intn(12); step > 0; step-- {
		var err error
		switch random.Intn(7) {
		case 0:
			steps = append(steps, "write a client hello")
			_, err = conn.Write(visionClientHelloRecord())
		case 1:
			steps = append(steps, "write a handshake record")
			_, err = conn.Write(visionHandshakeRecord())
		case 2:
			if options.handshakeOnly {
				continue
			}
			steps = append(steps, "write an application data record")
			_, err = conn.Write(visionApplicationDataRecord())
		case 3:
			if options.handshakeOnly {
				continue
			}
			steps = append(steps, "write a handshake record and a large application data record at once")
			_, err = conn.Write(visionHandshakeThenLargeApplicationData())
		case 4:
			if unread > 0 && !peerStalled {
				steps = append(steps, "short read")
				err = readSome(false)
			}
		case 5, 6:
			if peerStalled {
				continue
			}
			if unread > 0 {
				steps = append(steps, "read what the peer sent before")
				if err = readSome(true); err != nil {
					break
				}
			}
			switch peerCommand {
			case commandPaddingContinue:
				command := []byte{commandPaddingContinue, commandPaddingContinue, commandPaddingDirect, commandPaddingEnd}[random.Intn(4)]
				content := visionApplicationDataRecord()
				if command == commandPaddingContinue {
					cipher := ciphers[random.Intn(len(ciphers))]
					tls13 := random.Intn(5) != 0
					content = visionServerHelloRecord(cipher, tls13)
					steps = append(steps, fmt.Sprintf("peer sends a server hello cipher %#x tls13 %v", cipher, tls13))
				} else {
					steps = append(steps, fmt.Sprintf("peer sends a frame with command %d", command))
				}
				headerLen := 5
				if peerFrames == 0 {
					headerLen = 21
				}
				frame := visionTestFrame(peerFrames == 0, command, content, random.Intn(1400))
				peerFrames++
				switch {
				case command == commandPaddingContinue && random.Intn(3) == 0:
					split := headerLen + 79 + random.Intn(len(content)-79)
					steps = append(steps, fmt.Sprintf("in two TLS records split at %d", split))
					if _, err = pair.server.Write(frame[:split]); err == nil {
						_, err = pair.server.Write(frame[split:])
					}
					unread += len(content)
					if err == nil {
						err = readSome(true)
					}
				case command != commandPaddingDirect && random.Intn(4) == 0:
					split := 1 + random.Intn(len(frame)-1)
					if peerFrames == 1 {
						split = 21 + random.Intn(len(frame)-21)
					} else if random.Intn(2) == 0 {
						split = 1 + random.Intn(4)
					}
					steps = append(steps, fmt.Sprintf("only the first %d bytes arrive", split))
					_, err = pair.server.Write(frame[:split])
					peerStalled = true
					for err == nil {
						var n int
						n, err = readVisionPeerContentWithin(conn, 1+random.Intn(64), 100*time.Millisecond)
						unread -= n
						if netErr, isNet := err.(net.Error); isNet && netErr.Timeout() {
							err = nil
							break
						}
					}
				default:
					_, err = pair.server.Write(frame)
					unread += len(content)
					if command == commandPaddingDirect {
						unread += conn.input.Len() + conn.rawInput.Len()
					}
					if err == nil {
						err = readSome(command == commandPaddingDirect || random.Intn(2) == 0)
					}
					if command == commandPaddingDirect && err == nil && !conn.directRead {
						err = errors.New("the peer's direct frame did not switch the read side")
					}
				}
				peerCommand = command
			case commandPaddingDirect:
				if unread > 0 {
					continue
				}
				steps = append(steps, "peer sends raw bytes")
				_, err = pair.serverRaw.Write(visionApplicationDataRecord())
				unread += len(visionApplicationDataRecord())
				if err == nil {
					err = readSome(true)
				}
			case commandPaddingEnd:
				steps = append(steps, "peer sends plain bytes")
				_, err = pair.server.Write(visionApplicationDataRecord())
				unread += len(visionApplicationDataRecord())
				if err == nil {
					err = readSome(random.Intn(2) == 0)
				}
			}
		}
		if err != nil {
			return steps, err
		}
	}
	if !peerStalled && unread > 0 && random.Intn(2) == 0 {
		if err := readSome(true); err != nil {
			return steps, err
		}
	}
	ending := 0
	if options.mayEndOnPeerFrame && peerCommand == commandPaddingContinue && !peerStalled && unread == 0 {
		ending = random.Intn(5)
	}
	switch ending {
	case 1:
		steps = append(steps, "peer sends a direct frame last")
		if _, err := pair.server.Write(visionTestFrame(peerFrames == 0, commandPaddingDirect, visionApplicationDataRecord(), random.Intn(1400))); err != nil {
			return steps, err
		}
		unread += len(visionApplicationDataRecord()) + conn.input.Len() + conn.rawInput.Len()
		if err := readSome(true); err != nil {
			return steps, err
		}
		if !conn.directRead {
			return steps, errors.New("the peer's direct frame did not switch the read side")
		}
	case 2, 3:
		content := visionLargeApplicationDataRecord()[:200]
		frame := visionTestFrame(peerFrames == 0, commandPaddingContinue, content, random.Intn(1400))
		headerLen := 5
		if peerFrames == 0 {
			headerLen = 21
		}
		cut := headerLen + 1 + random.Intn(len(content)-1)
		if ending == 2 && peerFrames > 0 {
			cut = 1 + random.Intn(4)
		}
		steps = append(steps, fmt.Sprintf("peer sends the first %d bytes of a frame last", cut))
		if _, err := pair.server.Write(frame[:cut]); err != nil {
			return steps, err
		}
		peerStalled = true
		for {
			_, err := readVisionPeerContentWithin(conn, 1+random.Intn(64), 100*time.Millisecond)
			if netErr, isNet := err.(net.Error); isNet && netErr.Timeout() {
				break
			}
			if err != nil {
				return steps, err
			}
		}
	case 4:
		content := visionLargeApplicationDataRecord()[:200]
		steps = append(steps, "peer sends a frame last and the client reads part of it")
		if _, err := pair.server.Write(visionTestFrame(peerFrames == 0, commandPaddingContinue, content, random.Intn(1400))); err != nil {
			return steps, err
		}
		n, err := readVisionPeerContentWithin(conn, 1+random.Intn(64), 5*time.Second)
		if err != nil {
			return steps, err
		}
		unread += len(content) - n
	}
	if peerStalled || unread > 0 {
		steps = append(steps, "close with peer data buffered in VisionConn or a peer frame cut short")
	}
	return steps, nil
}

func TestVisionCloseOnRealConnsAcrossStates(t *testing.T) {
	random := mathrand.New(mathrand.NewSource(20261104))
	closeNotifyHeader := []byte{0x17, 0x03, 0x03, 0x00, 0x13}
	coverage := map[string]int{}
	for iteration := 0; iteration < 300; iteration++ {
		pair := newVisionTLSPair(t)
		tlsSide := &visionPlaintextRecorder{Conn: pair.client}
		conn := newFreshVisionConn(tlsSide, pair.client.NetConn())
		drained := make(chan visionReadResult, 1)
		go func() {
			data, err := io.ReadAll(pair.serverRaw)
			drained <- visionReadResult{data, err}
		}()
		steps, err := driveVisionRealConn(random, pair, conn, visionDriveOptions{})
		if err != nil {
			t.Fatalf("iteration %d after %v: %v", iteration, steps, err)
		}
		direct, err := visionWroteADirectFrame(tlsSide.wrote)
		if err != nil {
			t.Fatalf("iteration %d after %v: %v", iteration, steps, err)
		}
		if direct {
			coverage["direct"]++
			if conn.directRead {
				coverage["direct both ways"]++
			}
			if conn.remainingServerHello > 0 {
				coverage["direct with a partly read server hello"]++
			}
		} else {
			if conn.numberOfPacketToFilter > 0 {
				coverage["still filtering"]++
			}
			if !conn.isPadding {
				coverage["padding ended without a direct switch"]++
			}
			if conn.enableXTLS {
				coverage["XTLS without a direct frame"]++
			}
		}
		if len(conn.remainingBuffers) > 0 {
			coverage["buffered read data"]++
		}
		if conn.withinPaddingBuffers && conn.remainingContent > 0 {
			coverage["in the middle of peer content"]++
		}
		if conn.remainingContent == 0 && conn.remainingPadding > 0 {
			coverage["in the middle of peer padding"]++
		}
		if conn.paddingHeaderLen > 0 {
			coverage["split padding header"]++
		}
		if conn.input.Len() > 0 || conn.rawInput.Len() > 0 {
			coverage["unread TLS input"]++
		}
		closeDone := make(chan error, 1)
		go func() {
			closeDone <- conn.Close()
		}()
		select {
		case err = <-closeDone:
			if err != nil {
				t.Fatalf("iteration %d after %v: Close returned %v", iteration, steps, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d after %v: Close waited", iteration, steps)
		}
		if err = pair.client.NetConn().SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("iteration %d after %v: the client raw conn is still open after Close: %v", iteration, steps, err)
		}
		var data []byte
		select {
		case received := <-drained:
			data = received.data
			if received.err != nil {
				t.Fatalf("iteration %d after %v: the server saw %v instead of a clean end of stream", iteration, steps, received.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d after %v: the server never saw the end of the stream", iteration, steps)
		}
		if tcpConn, isTCP := pair.serverRaw.Conn.(*net.TCPConn); isTCP {
			tcpConn.SetLinger(0)
		}
		pair.serverRaw.Close()
		endsWithCloseNotify := len(data) >= 24 && bytes.Equal(data[len(data)-24:len(data)-19], closeNotifyHeader)
		if direct && endsWithCloseNotify {
			t.Fatalf("iteration %d after %v: a TLS record followed the direct stream", iteration, steps)
		}
		if !direct && !endsWithCloseNotify {
			t.Fatalf("iteration %d after %v: the stream ended without a close_notify record", iteration, steps)
		}
	}
	t.Logf("coverage %v", coverage)
	for _, name := range []string{
		"direct",
		"direct both ways",
		"direct with a partly read server hello",
		"still filtering",
		"padding ended without a direct switch",
		"XTLS without a direct frame",
		"buffered read data",
		"in the middle of peer content",
		"in the middle of peer padding",
		"split padding header",
		"unread TLS input",
	} {
		if coverage[name] == 0 {
			t.Fatalf("the generated states never reached %q: %v", name, coverage)
		}
	}
}

func TestVisionCloseDoesNotWaitForAWriteBlockedOnARealConn(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		enableXTLS bool
		firstWrite []byte
		wantRaw    bool
	}{
		{name: "padded writes on the TLS conn", enableXTLS: true},
		{name: "writes after the padding ended on the TLS conn", firstWrite: visionApplicationDataRecord()},
		{name: "direct writes on the raw conn", enableXTLS: true, firstWrite: visionApplicationDataRecord(), wantRaw: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			pair := newVisionTLSPair(t)
			tlsSide := &visionPlaintextRecorder{Conn: pair.client}
			rawSide := &visionRawWriteWatch{Conn: pair.client.NetConn()}
			conn := newFreshVisionConn(tlsSide, rawSide)
			conn.isTLS = true
			conn.isTLS12orAbove = true
			conn.enableXTLS = testCase.enableXTLS
			conn.numberOfPacketToFilter = 0
			if testCase.firstWrite != nil {
				if _, err := conn.Write(testCase.firstWrite); err != nil {
					t.Fatal(err)
				}
				if conn.isPadding {
					t.Fatal("the first write did not end the padding")
				}
			}
			direct, err := visionWroteADirectFrame(tlsSide.wrote)
			if err != nil {
				t.Fatal(err)
			}
			if direct != testCase.wantRaw {
				t.Fatalf("a direct frame went out: %v, want %v", direct, testCase.wantRaw)
			}
			tlsSide.stopRecord = true
			writingSince := &tlsSide.writingSince
			if testCase.wantRaw {
				writingSince = &rawSide.writingSince
			}
			writeDone := make(chan error, 1)
			go func() {
				chunk := make([]byte, 8000)
				for {
					if _, writeErr := conn.Write(chunk); writeErr != nil {
						writeDone <- writeErr
						return
					}
				}
			}()
			if _, err = waitForAStuckWrite(writeDone, 200*time.Millisecond, writingSince); err != nil {
				t.Fatal(err)
			}
			closeDone := make(chan error, 1)
			go func() {
				closeDone <- conn.Close()
			}()
			select {
			case <-closeDone:
			case <-time.After(5 * time.Second):
				t.Fatal("Close waited for a Write stuck on a real conn")
			}
			select {
			case err = <-writeDone:
				if err == nil {
					t.Fatal("the stuck write finished without an error after Close")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close did not release the stuck write")
			}
			if err = pair.client.NetConn().SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("client raw conn SetDeadline returned %v after Close, want net.ErrClosed", err)
			}
		})
	}
}

func TestVisionCloseDoesNotWaitForAWriteStuckOnARealConnAcrossStates(t *testing.T) {
	random := mathrand.New(mathrand.NewSource(20261105))
	coverage := map[string]int{}
	socketDir, err := os.MkdirTemp("", "vision")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "s")
	for iteration := 0; iteration < 400; iteration++ {
		underTLS := &visionRawWriteWatch{}
		pair := newVisionTLSPairOn(t, "unix", socketPath, func(conn net.Conn) net.Conn {
			underTLS.Conn = conn
			return underTLS
		})
		tlsSide := &visionPlaintextRecorder{Conn: pair.client}
		rawSide := &visionRawWriteWatch{Conn: underTLS.Conn}
		conn := newFreshVisionConn(tlsSide, rawSide)
		drained := make(chan error, 1)
		go func() {
			_, err := io.Copy(io.Discard, pair.serverRaw)
			drained <- err
		}()
		options := visionDriveOptions{handshakeOnly: random.Intn(2) == 0, mayEndOnPeerFrame: true}
		records := [][]byte{visionApplicationDataRecord(), visionHandshakeThenLargeApplicationData(), visionHandshakeRecord(), make([]byte, 8000)}
		if random.Intn(2) == 0 {
			options.handshakeOnly = true
			options.startWithXTLSHello = true
			records = records[:2]
		}
		steps, err := driveVisionRealConn(random, pair, conn, options)
		if options.handshakeOnly {
			steps = append([]string{"the client writes no application data"}, steps...)
		}
		if err != nil {
			t.Fatalf("iteration %d after %v: %v", iteration, steps, err)
		}
		direct, err := visionWroteADirectFrame(tlsSide.wrote)
		if err != nil {
			t.Fatalf("iteration %d after %v: %v", iteration, steps, err)
		}
		pair.serverRaw.SetReadDeadline(time.Now())
		if err = <-drained; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("iteration %d after %v: the peer stopped reading with %v", iteration, steps, err)
		}
		if err = fillVisionStreamSocket(underTLS.Conn); err != nil {
			t.Fatalf("iteration %d after %v: filling the socket ended with %v", iteration, steps, err)
		}
		record := records[random.Intn(len(records))]
		steps = append(steps, "the peer stops reading and the socket fills", fmt.Sprintf("write %d bytes starting %x", len(record), record[:3]))
		writeDone := make(chan error, 1)
		go func() {
			_, writeErr := conn.Write(record)
			writeDone <- writeErr
		}()
		stuckOn, err := waitForAStuckWrite(writeDone, 0, &underTLS.writingSince, &rawSide.writingSince)
		if err != nil {
			t.Fatalf("iteration %d after %v: %v", iteration, steps, err)
		}
		sides := []string{"TLS", "raw"}
		wantStuckOn := 0
		if direct {
			wantStuckOn = 1
		}
		if stuckOn != wantStuckOn {
			t.Fatalf("iteration %d after %v: the write got stuck on the %s conn, want the %s conn", iteration, steps, sides[stuckOn], sides[wantStuckOn])
		}
		closeDone := make(chan error, 1)
		go func() {
			closeDone <- conn.Close()
		}()
		select {
		case err = <-closeDone:
			if err != nil {
				t.Fatalf("iteration %d after %v: Close returned %v", iteration, steps, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d after %v: Close waited for a write stuck on the %s conn", iteration, steps, sides[stuckOn])
		}
		select {
		case err = <-writeDone:
			if err == nil {
				t.Fatalf("iteration %d after %v: the stuck write finished without an error after Close", iteration, steps)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d after %v: Close did not release the write stuck on the %s conn", iteration, steps, sides[stuckOn])
		}
		if err = pair.client.NetConn().SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("iteration %d after %v: the client raw conn is still open after Close: %v", iteration, steps, err)
		}
		pair.serverRaw.Close()
		switching, err := visionWroteADirectFrame(tlsSide.wrote)
		if err != nil {
			t.Fatalf("iteration %d after %v: %v", iteration, steps, err)
		}
		switching = switching && !direct
		switch {
		case switching:
			coverage["switching frame stuck on the TLS conn"]++
			if conn.directRead {
				coverage["switching frame stuck on the TLS conn after the peer's direct frame"]++
			} else {
				coverage["switching frame stuck on the TLS conn with the peer still padding"]++
			}
			if len(record) == len(visionHandshakeThenLargeApplicationData()) {
				coverage["switching frame stuck on the TLS conn behind a handshake record"]++
			}
			if conn.withinPaddingBuffers && conn.remainingContent > 0 {
				coverage["switching frame stuck on the TLS conn in the middle of peer content"]++
			}
			if len(conn.remainingBuffers) > 0 {
				coverage["switching frame stuck on the TLS conn with buffered read data"]++
			}
			if conn.paddingHeaderLen > 0 {
				coverage["switching frame stuck on the TLS conn with a split padding header"]++
			}
		case direct:
			coverage["stuck on the raw conn"]++
			if conn.directRead {
				coverage["stuck on the raw conn after the peer's direct frame"]++
			}
			if conn.withinPaddingBuffers && conn.remainingContent > 0 {
				coverage["stuck on the raw conn in the middle of peer content"]++
			}
			if len(conn.remainingBuffers) > 0 {
				coverage["stuck on the raw conn with buffered read data"]++
			}
			if conn.paddingHeaderLen > 0 {
				coverage["stuck on the raw conn with a split padding header"]++
			}
		default:
			coverage["stuck on the TLS conn"]++
			if conn.numberOfPacketToFilter > 0 {
				coverage["stuck on the TLS conn while filtering"]++
			}
			if conn.remainingContent != -1 {
				coverage["stuck on the TLS conn after a peer frame"]++
			}
			if conn.currentCommand == commandPaddingContinue && conn.remainingContent != -1 {
				coverage["stuck on the TLS conn after a peer Continue frame"]++
			}
			if !conn.isTLS12orAbove {
				coverage["stuck on the TLS conn before a server hello"]++
			}
			if conn.cipher != 0 {
				coverage["stuck on the TLS conn with the cipher known"]++
			}
			if conn.enableXTLS {
				coverage["stuck on the TLS conn with XTLS on"]++
			}
			if !conn.isPadding {
				coverage["stuck on the TLS conn after the padding ended"]++
			}
			if conn.withinPaddingBuffers && conn.remainingContent > 0 {
				coverage["stuck on the TLS conn in the middle of peer content"]++
			}
			if len(conn.remainingBuffers) > 0 {
				coverage["stuck on the TLS conn with buffered read data"]++
			}
			if conn.paddingHeaderLen > 0 {
				coverage["stuck on the TLS conn with a split padding header"]++
			}
		}
		if conn.input.Len() > 0 || conn.rawInput.Len() > 0 || len(conn.remainingBuffers) > 0 || conn.paddingHeaderLen > 0 {
			coverage["stuck with peer data left in VisionConn or the TLS conn"]++
		}
	}
	t.Logf("coverage %v", coverage)
	for _, name := range []string{
		"switching frame stuck on the TLS conn after the peer's direct frame",
		"switching frame stuck on the TLS conn with the peer still padding",
		"switching frame stuck on the TLS conn behind a handshake record",
		"switching frame stuck on the TLS conn in the middle of peer content",
		"switching frame stuck on the TLS conn with buffered read data",
		"switching frame stuck on the TLS conn with a split padding header",
		"stuck on the TLS conn in the middle of peer content",
		"stuck on the TLS conn with buffered read data",
		"stuck on the TLS conn with a split padding header",
		"stuck on the raw conn",
		"stuck on the raw conn after the peer's direct frame",
		"stuck on the TLS conn while filtering",
		"stuck on the TLS conn after a peer frame",
		"stuck on the TLS conn after a peer Continue frame",
		"stuck on the TLS conn before a server hello",
		"stuck on the TLS conn with the cipher known",
		"stuck on the TLS conn with XTLS on",
		"stuck on the TLS conn after the padding ended",
		"stuck with peer data left in VisionConn or the TLS conn",
	} {
		if coverage[name] == 0 {
			t.Fatalf("the generated states never reached %q: %v", name, coverage)
		}
	}
}
