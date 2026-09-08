package hysteria2

import (
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
)

const udpSocketBufferSize = 16 * 1024 * 1024

func setUDPSocketBuffers(conn net.PacketConn, logger logger.Logger) {
	if readSetter, ok := common.Cast[interface {
		SetReadBuffer(bytes int) error
	}](conn); ok {
		if err := readSetter.SetReadBuffer(udpSocketBufferSize); err != nil {
			logger.Warn("hysteria2: failed to request a ", udpSocketBufferSize, " byte udp receive buffer: ", err)
		}
	} else {
		logger.Warn("hysteria2: udp receive buffer size is not adjustable on this listener, upload throughput stays capped at the system default")
	}
	if writeSetter, ok := common.Cast[interface {
		SetWriteBuffer(bytes int) error
	}](conn); ok {
		if err := writeSetter.SetWriteBuffer(udpSocketBufferSize); err != nil {
			logger.Warn("hysteria2: failed to request a ", udpSocketBufferSize, " byte udp send buffer: ", err)
		}
	} else {
		logger.Warn("hysteria2: udp send buffer size is not adjustable on this listener, download throughput stays capped at the system default")
	}
	effectiveRead, effectiveWrite, err := readUDPSocketBuffers(conn)
	if err != nil {
		logger.Warn("hysteria2: cannot verify the effective udp socket buffer sizes: ", err)
		return
	}
	usableRead := effectiveRead / udpSocketBufferReadbackFactor
	usableWrite := effectiveWrite / udpSocketBufferReadbackFactor
	if usableRead < udpSocketBufferSize {
		logger.Warn("hysteria2: kernel granted only ", usableRead, " of the ", udpSocketBufferSize,
			" bytes requested for the udp receive buffer, raise ", udpReceiveBufferLimitName,
			" or upload throughput stays limited")
	}
	if usableWrite < udpSocketBufferSize {
		logger.Warn("hysteria2: kernel granted only ", usableWrite, " of the ", udpSocketBufferSize,
			" bytes requested for the udp send buffer, raise ", udpSendBufferLimitName,
			" or download throughput stays limited")
	}
	logger.Info("hysteria2: udp socket buffers requested=", udpSocketBufferSize,
		" granted_rcv=", usableRead, " granted_snd=", usableWrite,
		" kernel_rcv=", effectiveRead, " kernel_snd=", effectiveWrite)
}
