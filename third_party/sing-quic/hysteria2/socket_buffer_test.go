package hysteria2

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

type recordingLogger struct {
	warns []string
	infos []string
}

func render(args []any) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, fmt.Sprint(a))
	}
	return strings.Join(parts, "")
}

func (l *recordingLogger) Trace(args ...any) {}
func (l *recordingLogger) Debug(args ...any) {}
func (l *recordingLogger) Info(args ...any)  { l.infos = append(l.infos, render(args)) }
func (l *recordingLogger) Warn(args ...any)  { l.warns = append(l.warns, render(args)) }
func (l *recordingLogger) Error(args ...any) {}
func (l *recordingLogger) Fatal(args ...any) {}
func (l *recordingLogger) Panic(args ...any) {}

func (l *recordingLogger) warnedAbout(fragment string) bool {
	for _, w := range l.warns {
		if strings.Contains(w, fragment) {
			return true
		}
	}
	return false
}

type bareConn struct{}

func (bareConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, errors.New("unused") }
func (bareConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, errors.New("unused") }
func (bareConn) Close() error                           { return nil }
func (bareConn) LocalAddr() net.Addr                    { return nil }
func (bareConn) SetDeadline(time.Time) error            { return nil }
func (bareConn) SetReadDeadline(time.Time) error        { return nil }
func (bareConn) SetWriteDeadline(time.Time) error       { return nil }

type failingSetterConn struct{ bareConn }

func (failingSetterConn) SetReadBuffer(int) error  { return errors.New("read setter refused") }
func (failingSetterConn) SetWriteBuffer(int) error { return errors.New("write setter refused") }

type acceptingSetterConn struct {
	bareConn
	readAsked  int
	writeAsked int
}

func (c *acceptingSetterConn) SetReadBuffer(bytes int) error  { c.readAsked = bytes; return nil }
func (c *acceptingSetterConn) SetWriteBuffer(bytes int) error { c.writeAsked = bytes; return nil }

func TestNonAdjustableSocketWarnsForBothDirections(t *testing.T) {
	l := &recordingLogger{}
	setUDPSocketBuffers(bareConn{}, l)
	if !l.warnedAbout("udp receive buffer size is not adjustable") {
		t.Fatalf("no receive-side warning, got %v", l.warns)
	}
	if !l.warnedAbout("udp send buffer size is not adjustable") {
		t.Fatalf("no send-side warning, got %v", l.warns)
	}
}

func TestFailedSettersAreReported(t *testing.T) {
	l := &recordingLogger{}
	setUDPSocketBuffers(failingSetterConn{}, l)
	if !l.warnedAbout("read setter refused") {
		t.Fatalf("read setter error not surfaced, got %v", l.warns)
	}
	if !l.warnedAbout("write setter refused") {
		t.Fatalf("write setter error not surfaced, got %v", l.warns)
	}
}

func TestUnverifiableReadbackWarnsInsteadOfStayingSilent(t *testing.T) {
	l := &recordingLogger{}
	c := &acceptingSetterConn{}
	setUDPSocketBuffers(c, l)
	if c.readAsked != udpSocketBufferSize || c.writeAsked != udpSocketBufferSize {
		t.Fatalf("requested %d/%d, want %d", c.readAsked, c.writeAsked, udpSocketBufferSize)
	}
	if !l.warnedAbout("cannot verify the effective udp socket buffer sizes") {
		t.Fatalf("readback failure was silent, got %v", l.warns)
	}
}

func TestRealSocketReportsGrantedAgainstRequested(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a udp socket: %v", err)
	}
	defer conn.Close()
	l := &recordingLogger{}
	setUDPSocketBuffers(conn, l)
	if len(l.infos) != 1 {
		t.Fatalf("expected exactly one summary line, got %v", l.infos)
	}
	summary := l.infos[0]
	for _, want := range []string{"requested=", "granted_rcv=", "granted_snd=", "kernel_rcv=", "kernel_snd="} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary %q is missing %q", summary, want)
		}
	}
	if l.warnedAbout("is not adjustable") || l.warnedAbout("cannot verify") {
		t.Fatalf("a real udp socket should be adjustable and verifiable, got %v", l.warns)
	}
}

func TestShortfallWarningTracksTheGrantedSize(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a udp socket: %v", err)
	}
	defer conn.Close()
	l := &recordingLogger{}
	setUDPSocketBuffers(conn, l)
	rawRead, rawWrite, err := readUDPSocketBuffers(conn)
	if err != nil {
		t.Fatalf("readback failed: %v", err)
	}
	grantedRead := rawRead / udpSocketBufferReadbackFactor
	grantedWrite := rawWrite / udpSocketBufferReadbackFactor
	warnedRead := l.warnedAbout("for the udp receive buffer")
	warnedWrite := l.warnedAbout("for the udp send buffer")
	if (grantedRead < udpSocketBufferSize) != warnedRead {
		t.Fatalf("granted_rcv=%d requested=%d warned=%v", grantedRead, udpSocketBufferSize, warnedRead)
	}
	if (grantedWrite < udpSocketBufferSize) != warnedWrite {
		t.Fatalf("granted_snd=%d requested=%d warned=%v", grantedWrite, udpSocketBufferSize, warnedWrite)
	}
	if !strings.Contains(l.infos[0], fmt.Sprintf("granted_rcv=%d", grantedRead)) {
		t.Fatalf("summary %q does not report granted_rcv=%d", l.infos[0], grantedRead)
	}
	if !strings.Contains(l.infos[0], fmt.Sprintf("kernel_rcv=%d", rawRead)) {
		t.Fatalf("summary %q does not report kernel_rcv=%d", l.infos[0], rawRead)
	}
}
