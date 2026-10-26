package ja3_test

import (
	"encoding/binary"
	"testing"

	"github.com/sagernet/sing-box/common/ja3"

	"github.com/stretchr/testify/require"
)

func tlsExtension(extensionType uint16, data []byte) []byte {
	extension := binary.BigEndian.AppendUint16(nil, extensionType)
	extension = binary.BigEndian.AppendUint16(extension, uint16(len(data)))
	return append(extension, data...)
}

func clientHelloRecord(extensions ...[]byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	var extensionBytes []byte
	for _, extension := range extensions {
		extensionBytes = append(extensionBytes, extension...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensionBytes)))
	body = append(body, extensionBytes...)
	message := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := []byte{0x16, 0x03, 0x03}
	record = binary.BigEndian.AppendUint16(record, uint16(len(message)))
	return append(record, message...)
}

func TestComputeReadsVersionsAndSignatureAlgorithms(t *testing.T) {
	t.Parallel()
	fingerprint, err := ja3.Compute(clientHelloRecord(
		tlsExtension(43, []byte{0x04, 0x03, 0x04, 0x03, 0x03}),
		tlsExtension(13, []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04}),
	))
	require.NoError(t, err)
	require.Equal(t, []uint16{0x0304, 0x0303}, fingerprint.Versions)
	require.Equal(t, []uint16{0x0403, 0x0804}, fingerprint.SignatureAlgorithms)
}

func TestComputeRejectsTruncatedLengthPrefixedExtensions(t *testing.T) {
	t.Parallel()
	for name, extension := range map[string][]byte{
		"supported_versions":         tlsExtension(43, []byte{0xfe}),
		"supported_versions_partial": tlsExtension(43, []byte{0x08, 0x03, 0x04}),
		"signature_algorithms":       tlsExtension(13, []byte{0x00, 0x10}),
		"signature_algorithms_odd":   tlsExtension(13, []byte{0x00, 0x08, 0x04, 0x03}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var err error
			require.NotPanics(t, func() {
				_, err = ja3.Compute(clientHelloRecord(extension))
			})
			require.Error(t, err)
		})
	}
}
