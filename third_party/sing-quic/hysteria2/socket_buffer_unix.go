//go:build unix

package hysteria2

import (
	"net"
	"os"
	"syscall"

	"github.com/sagernet/sing/common"
)

func readUDPSocketBuffers(conn net.PacketConn) (int, int, error) {
	rawConnSource, ok := common.Cast[interface {
		SyscallConn() (syscall.RawConn, error)
	}](conn)
	if !ok {
		return 0, 0, os.ErrInvalid
	}
	rawConn, err := rawConnSource.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var (
		readSize, writeSize int
		readErr, writeErr   error
	)
	controlErr := rawConn.Control(func(fd uintptr) {
		readSize, readErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		writeSize, writeErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	})
	if controlErr != nil {
		return 0, 0, controlErr
	}
	if readErr != nil {
		return 0, 0, readErr
	}
	if writeErr != nil {
		return 0, 0, writeErr
	}
	return readSize, writeSize, nil
}
