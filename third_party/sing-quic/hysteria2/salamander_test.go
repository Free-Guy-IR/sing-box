package hysteria2

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

const salamanderTestPasswordLength = 36

func salamanderPasswordWithSpareCapacity() []byte {
	password := make([]byte, salamanderTestPasswordLength, salamanderTestPasswordLength+2*salamanderSaltLen)
	for index := range password {
		password[index] = byte('a' + index%26)
	}
	spare := password[len(password):cap(password)]
	for index := range spare {
		spare[index] = 0xee
	}
	return password
}

func listenLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type nonVectorisedPacketConn struct {
	net.PacketConn
}

func readSalamanderPacket(t *testing.T, conn net.PacketConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return buffer[:n]
}

func TestSalamanderLeavesPasswordBackingArrayUntouched(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		vectorised bool
	}{
		{name: "vectorised", vectorised: true},
		{name: "plain", vectorised: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			password := salamanderPasswordWithSpareCapacity()
			backingBefore := bytes.Clone(password[:cap(password)])
			serverUDP := listenLoopbackUDP(t)
			clientUDP := listenLoopbackUDP(t)
			var serverPacketConn net.PacketConn = serverUDP
			if !testCase.vectorised {
				serverPacketConn = nonVectorisedPacketConn{serverUDP}
			}
			server := NewSalamanderConn(serverPacketConn, password)
			if _, isVectorised := server.(*VectorisedSalamanderPacketConn); isVectorised != testCase.vectorised {
				t.Fatalf("vectorised salamander conn = %v, want %v", isVectorised, testCase.vectorised)
			}
			client := NewSalamanderConn(clientUDP, bytes.Clone(password))
			payload := []byte("salamander payload")

			if _, err := client.WriteTo(bytes.Clone(payload), serverUDP.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			if received := readSalamanderPacket(t, server); !bytes.Equal(received, payload) {
				t.Fatalf("server decoded %q, want %q", received, payload)
			}
			if _, err := server.WriteTo(bytes.Clone(payload), clientUDP.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			if received := readSalamanderPacket(t, client); !bytes.Equal(received, payload) {
				t.Fatalf("client decoded %q, want %q", received, payload)
			}

			if backingAfter := password[:cap(password)]; !bytes.Equal(backingAfter, backingBefore) {
				t.Fatalf("salamander wrote salts into the spare capacity of the caller's password: before %x, after %x",
					backingBefore[len(password):], backingAfter[len(password):])
			}
		})
	}
}

func TestSalamanderConcurrentReadAndWriteDecodeEveryPacket(t *testing.T) {
	password := salamanderPasswordWithSpareCapacity()
	serverUDP := listenLoopbackUDP(t)
	clientUDP := listenLoopbackUDP(t)
	sinkUDP := listenLoopbackUDP(t)
	server := NewSalamanderConn(serverUDP, password)
	client := NewSalamanderConn(clientUDP, bytes.Clone(password))
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	outgoing := bytes.Repeat([]byte{0x11}, 1200)
	const packetCount = 5000

	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(2)
	go func() {
		defer writers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = server.WriteTo(bytes.Clone(outgoing), sinkUDP.LocalAddr())
		}
	}()
	go func() {
		defer writers.Done()
		for index := 0; index < packetCount; index++ {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = client.WriteTo(bytes.Clone(payload), serverUDP.LocalAddr())
			if index%64 == 63 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	var received, misdecoded int
	buffer := make([]byte, 2048)
	for received < packetCount {
		if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := server.ReadFrom(buffer)
		if err != nil {
			break
		}
		received++
		if !bytes.Equal(buffer[:n], payload) {
			misdecoded++
		}
	}
	close(stop)
	writers.Wait()

	if received == 0 {
		t.Fatal("no packet reached the server")
	}
	if misdecoded > 0 {
		t.Fatalf("%d of %d packets were decoded with a key built from another packet's salt", misdecoded, received)
	}
}
