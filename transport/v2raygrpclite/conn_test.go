package v2raygrpclite

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGunConnRejectsFrameLengthBeyondInt(t *testing.T) {
	t.Parallel()
	frame := binary.AppendUvarint([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x0a}, 1<<63)
	conn := newGunConn(bytes.NewReader(frame), io.Discard, nil)
	var err error
	require.NotPanics(t, func() {
		_, err = conn.Read(make([]byte, 64))
	})
	require.Error(t, err)
}
