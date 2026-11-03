package hysteria

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

const hopTestWait = 2 * time.Second

type observedPacketConn struct {
	net.PacketConn
	udpConn     *net.UDPConn
	reads       atomic.Int64
	sawEMSGSIZE atomic.Bool
}

func (c *observedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.reads.Add(1)
	n, addr, err := c.PacketConn.ReadFrom(p)
	if errors.Is(err, syscall.EMSGSIZE) {
		c.sawEMSGSIZE.Store(true)
	}
	return n, addr, err
}

func TestHopPacketConnRecvLoopStopsAfterClose(t *testing.T) {
	hopConn, server, observed := newObservedHopPacketConn(t, nil)
	deliverThroughHop(t, hopConn, server, observed, "first")
	if err := hopConn.Close(); err != nil {
		t.Fatal(err)
	}
	assertRecvLoopStopped(t, observed)
}

func TestHopPacketConnDeliversReadTimeout(t *testing.T) {
	hopConn, server, observed := newObservedHopPacketConn(t, nil)
	deliverThroughHop(t, hopConn, server, observed, "first")
	if err := hopConn.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err := readHopWithin(hopConn, hopTestWait)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("ReadFrom after a past read deadline: err=%v, want a timeout", err)
	}
	assertRecvLoopStopped(t, observed)
}

func newObservedHopPacketConn(t *testing.T, configure func(*testing.T, *net.UDPConn)) (*HopPacketConn, *net.UDPConn, *observedPacketConn) {
	server := listenLoopbackUDP(t)
	serverPort := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	var dialedAccess sync.Mutex
	var dialed []*observedPacketConn
	dialFunc := func(addr M.Socksaddr) (net.PacketConn, error) {
		udpConn, err := net.DialUDP("udp4", nil, addr.UDPAddr())
		if err != nil {
			return nil, err
		}
		if configure != nil {
			configure(t, udpConn)
		}
		conn := &observedPacketConn{PacketConn: bufio.NewUnbindPacketConn(udpConn), udpConn: udpConn}
		dialedAccess.Lock()
		dialed = append(dialed, conn)
		dialedAccess.Unlock()
		return conn, nil
	}
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 0)
	hopConn, err := NewHopPacketConn(dialFunc, destination, []uint16{serverPort}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hopConn.Close() })
	dialedAccess.Lock()
	defer dialedAccess.Unlock()
	if len(dialed) != 1 {
		t.Fatalf("NewHopPacketConn dialed %d conns, want 1", len(dialed))
	}
	return hopConn, server, dialed[0]
}

func deliverThroughHop(t *testing.T, hopConn *HopPacketConn, server *net.UDPConn, observed *observedPacketConn, payload string) {
	if _, err := server.WriteToUDP([]byte(payload), observed.udpConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	got, err := readHopWithin(hopConn, hopTestWait)
	if err != nil || got != payload {
		t.Fatalf("datagram through HopPacketConn: got %q err=%v, want %q", got, err, payload)
	}
}

func assertRecvLoopStopped(t *testing.T, observed *observedPacketConn) {
	deadline := time.Now().Add(hopTestWait)
	for runningRecvLoops() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d HopPacketConn recvLoop goroutines still running after %v", runningRecvLoops(), hopTestWait)
		}
		time.Sleep(10 * time.Millisecond)
	}
	settled := observed.reads.Load()
	time.Sleep(200 * time.Millisecond)
	if reads := observed.reads.Load(); reads != settled {
		t.Fatalf("recvLoop kept reading after it should have returned: %d reads, then %d", settled, reads)
	}
}

func runningRecvLoops() int {
	stacks := make([]byte, 1<<20)
	n := runtime.Stack(stacks, true)
	return strings.Count(string(stacks[:n]), ".(*HopPacketConn).recvLoop(")
}

type hopReadResult struct {
	payload string
	err     error
}

var errHopReadTimeout = errors.New("no datagram from HopPacketConn within the wait")

func readHopWithin(hopConn *HopPacketConn, wait time.Duration) (string, error) {
	result := make(chan hopReadResult, 1)
	go func() {
		buffer := make([]byte, udpBufferSize)
		n, _, err := hopConn.ReadFrom(buffer)
		result <- hopReadResult{string(buffer[:n]), err}
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case r := <-result:
		return r.payload, r.err
	case <-timer.C:
		return "", errHopReadTimeout
	}
}

func listenLoopbackUDP(t *testing.T) *net.UDPConn {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}
