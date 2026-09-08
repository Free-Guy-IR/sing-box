//go:build !unix

package hysteria2

import (
	"net"
	"os"
)

func readUDPSocketBuffers(conn net.PacketConn) (int, int, error) {
	return 0, 0, os.ErrInvalid
}
