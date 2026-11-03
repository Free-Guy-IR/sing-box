//go:build linux

package hysteria

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestHopPacketConnSurvivesEMSGSIZE(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("raw ICMP socket unavailable: %v", err)
	}
	_ = syscall.Close(fd)
	if !t.Run("control", testConnectedUDPReportsEMSGSIZE) {
		t.Fatal("INCONCLUSIVE: the kernel did not report EMSGSIZE on a connected UDP socket")
	}
	t.Run("hop", testHopPacketConnDeliversAfterEMSGSIZE)
}

func testConnectedUDPReportsEMSGSIZE(t *testing.T) {
	server := listenLoopbackUDP(t)
	serverAddr := server.LocalAddr().(*net.UDPAddr)
	client, err := net.DialUDP("udp4", nil, serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	setPMTUDiscProbe(t, client)
	clientAddr := client.LocalAddr().(*net.UDPAddr)

	buffer := make([]byte, udpBufferSize)
	if _, err = server.WriteToUDP([]byte("first"), clientAddr); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(hopTestWait))
	n, err := client.Read(buffer)
	if err != nil || string(buffer[:n]) != "first" {
		t.Fatalf("first datagram: got %q err=%v", buffer[:n], err)
	}

	sendICMPFragNeeded(t, clientAddr, serverAddr, 1280)
	_ = client.SetReadDeadline(time.Now().Add(hopTestWait))
	_, err = client.Read(buffer)
	if !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("read after ICMP frag-needed: err=%v, want EMSGSIZE", err)
	}
	t.Logf("control: connected socket read returned %v", err)

	if _, err = server.WriteToUDP([]byte("after"), clientAddr); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(hopTestWait))
	n, err = client.Read(buffer)
	if err != nil || string(buffer[:n]) != "after" {
		t.Fatalf("datagram after EMSGSIZE on the plain socket: got %q err=%v", buffer[:n], err)
	}
	t.Logf("control: the same socket delivered %q after EMSGSIZE", buffer[:n])
}

func testHopPacketConnDeliversAfterEMSGSIZE(t *testing.T) {
	hopConn, server, observed := newObservedHopPacketConn(t, setPMTUDiscProbe)
	serverAddr := server.LocalAddr().(*net.UDPAddr)
	clientAddr := observed.udpConn.LocalAddr().(*net.UDPAddr)
	deliverThroughHop(t, hopConn, server, observed, "first")

	sendICMPFragNeeded(t, clientAddr, serverAddr, 1280)
	waitForRecvLoopEMSGSIZE(t, observed)

	if _, err := server.WriteToUDP([]byte("after"), clientAddr); err != nil {
		t.Fatal(err)
	}
	payload, err := readHopWithin(hopConn, hopTestWait)
	if err != nil || payload != "after" {
		_ = observed.udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buffer := make([]byte, udpBufferSize)
		n, directErr := observed.udpConn.Read(buffer)
		t.Fatalf("HopPacketConn.ReadFrom after recvLoop read EMSGSIZE: got %q err=%v; the hop socket itself still held %q (err=%v), so recvLoop stopped reading it", payload, err, buffer[:n], directErr)
	}
	t.Logf("hop: recvLoop read EMSGSIZE and HopPacketConn still delivered %q", payload)
}

func waitForRecvLoopEMSGSIZE(t *testing.T, observed *observedPacketConn) {
	deadline := time.Now().Add(hopTestWait)
	for !observed.sawEMSGSIZE.Load() {
		if time.Now().After(deadline) {
			t.Fatal("INCONCLUSIVE: recvLoop never read EMSGSIZE after the ICMP frag-needed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func setPMTUDiscProbe(t *testing.T, conn *net.UDPConn) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
	})
	if err == nil {
		err = sockErr
	}
	if err != nil {
		t.Fatal(err)
	}
}

func sendICMPFragNeeded(t *testing.T, client, server *net.UDPAddr, mtu uint16) {
	const oversizedPayload = 1400
	inner := make([]byte, 28)
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:], uint16(len(inner)+oversizedPayload))
	binary.BigEndian.PutUint16(inner[4:], 0x1234)
	binary.BigEndian.PutUint16(inner[6:], 0x4000)
	inner[8] = 64
	inner[9] = syscall.IPPROTO_UDP
	copy(inner[12:16], client.IP.To4())
	copy(inner[16:20], server.IP.To4())
	binary.BigEndian.PutUint16(inner[10:], internetChecksum(inner[:20]))
	binary.BigEndian.PutUint16(inner[20:], uint16(client.Port))
	binary.BigEndian.PutUint16(inner[22:], uint16(server.Port))
	binary.BigEndian.PutUint16(inner[24:], uint16(8+oversizedPayload))

	packet := make([]byte, 8+len(inner))
	packet[0] = 3
	packet[1] = 4
	binary.BigEndian.PutUint16(packet[6:], mtu)
	copy(packet[8:], inner)
	binary.BigEndian.PutUint16(packet[2:], internetChecksum(packet))

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	target := &syscall.SockaddrInet4{}
	copy(target.Addr[:], client.IP.To4())
	if err = syscall.Sendto(fd, packet, 0, target); err != nil {
		t.Fatal(err)
	}
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
