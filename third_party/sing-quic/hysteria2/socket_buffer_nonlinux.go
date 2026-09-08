//go:build !linux

package hysteria2

const (
	udpSocketBufferReadbackFactor = 1
	udpReceiveBufferLimitName     = "the system udp receive buffer limit"
	udpSendBufferLimitName        = "the system udp send buffer limit"
)
