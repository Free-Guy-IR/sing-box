//go:build !unix

package vless

import (
	"errors"
	"net"
)

func fillVisionStreamSocket(conn net.Conn) error {
	return errors.ErrUnsupported
}
