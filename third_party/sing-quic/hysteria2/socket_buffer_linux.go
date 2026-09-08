//go:build linux

package hysteria2

const (
	udpSocketBufferReadbackFactor = 2
	udpReceiveBufferLimitName     = "net.core.rmem_max"
	udpSendBufferLimitName        = "net.core.wmem_max"
)
