//go:build unix

package vless

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

func newVisionUnixStreamConns(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]net.Conn, len(fds))
	for index, fd := range fds {
		file := os.NewFile(uintptr(fd), "vision-unix-stream")
		conns[index], err = net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conns[index].Close() })
	}
	return conns[0], conns[1]
}

func fillVisionStreamSocket(conn net.Conn) error {
	syscallConn, isSyscallConn := conn.(syscall.Conn)
	if !isSyscallConn {
		return fmt.Errorf("%T has no file descriptor to fill", conn)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return err
	}
	garbage := make([]byte, 64<<10)
	for _, size := range []int{len(garbage), 1} {
		for {
			var writeErr error
			if err = rawConn.Write(func(fd uintptr) bool {
				_, writeErr = syscall.Write(int(fd), garbage[:size])
				return true
			}); err != nil {
				return err
			}
			if errors.Is(writeErr, syscall.EAGAIN) {
				break
			}
			if writeErr != nil && !errors.Is(writeErr, syscall.EINTR) {
				return writeErr
			}
		}
	}
	return nil
}
