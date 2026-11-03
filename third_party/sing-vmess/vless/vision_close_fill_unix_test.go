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
	first, err := visionUnixStreamConn(fds[0])
	if err != nil {
		syscall.Close(fds[1])
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Close() })
	second, err := visionUnixStreamConn(fds[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	return first, second
}

func visionUnixStreamConn(fd int) (net.Conn, error) {
	file := os.NewFile(uintptr(fd), "vision-unix-stream")
	defer file.Close()
	return net.FileConn(file)
}

func TestVisionUnixStreamConnsCleanupClosesBothEnds(t *testing.T) {
	var first, second net.Conn
	if !t.Run("pair", func(t *testing.T) {
		first, second = newVisionUnixStreamConns(t)
	}) {
		t.FailNow()
	}
	if first == nil || second == nil {
		t.Skip("the pair subtest did not run")
	}
	for name, conn := range map[string]net.Conn{"first": first, "second": second} {
		if _, err := conn.Write([]byte{0}); !errors.Is(err, net.ErrClosed) {
			t.Errorf("write on the %s end after the cleanups returned %v, want %v", name, err, net.ErrClosed)
		}
		if err := conn.Close(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("close of the %s end after the cleanups returned %v, want %v", name, err, net.ErrClosed)
		}
	}
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
