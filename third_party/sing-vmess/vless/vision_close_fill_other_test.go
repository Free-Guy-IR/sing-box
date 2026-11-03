//go:build !unix

package vless

import (
	"errors"
	"net"
	"testing"
)

func newVisionUnixStreamConns(t *testing.T) (net.Conn, net.Conn) {
	t.Skip("a deterministic stuck write needs a Unix stream socket pair")
	return nil, nil
}

func fillVisionStreamSocket(conn net.Conn) error {
	return errors.ErrUnsupported
}
