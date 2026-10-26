package sniff_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/common/sniff/internal/qtls"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func quicVarint(value uint64) []byte {
	if value < 1<<6 {
		return []byte{byte(value)}
	}
	return []byte{0x40 | byte(value>>8), byte(value)}
}

func quicCryptoFrame(declaredLength uint64, data []byte) []byte {
	frame := append([]byte{0x06}, quicVarint(0)...)
	frame = append(frame, quicVarint(declaredLength)...)
	return append(frame, data...)
}

func sealQUICInitial(t *testing.T, frames []byte) []byte {
	t.Helper()
	destConnID := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, qtls.SaltV1)
	secret := qtls.HKDFExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	aead := qtls.AEADAESGCMTLS13(
		qtls.HKDFExpandLabel(crypto.SHA256, secret, []byte{}, qtls.HKDFLabelKeyV1, 16),
		qtls.HKDFExpandLabel(crypto.SHA256, secret, []byte{}, qtls.HKDFLabelIVV1, 12),
	)
	headerProtection, err := aes.NewCipher(qtls.HKDFExpandLabel(crypto.SHA256, secret, []byte{}, qtls.HKDFLabelHeaderProtectionV1, 16))
	require.NoError(t, err)

	plaintext := make([]byte, max(1100, len(frames)))
	copy(plaintext, frames)
	const packetNumber = 2
	const packetNumberLength = 4
	header := []byte{0xc0 | (packetNumberLength - 1), 0x00, 0x00, 0x00, 0x01, byte(len(destConnID))}
	header = append(header, destConnID...)
	header = append(header, 0x00, 0x00)
	header = append(header, quicVarint(uint64(packetNumberLength+len(plaintext)+aead.Overhead()))...)
	packetNumberOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, packetNumber)
	nonce := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(nonce, packetNumber)
	packet := aead.Seal(bytes.Clone(header), nonce, plaintext, header)

	mask := make([]byte, aes.BlockSize)
	headerProtection.Encrypt(mask, packet[packetNumberOffset+4:packetNumberOffset+4+aes.BlockSize])
	packet[0] ^= mask[0] & 0x0f
	for i := range packetNumberLength {
		packet[packetNumberOffset+i] ^= mask[1+i]
	}
	return packet
}

func quicTLSExtension(extensionType uint16, data []byte) []byte {
	extension := binary.BigEndian.AppendUint16(nil, extensionType)
	extension = binary.BigEndian.AppendUint16(extension, uint16(len(data)))
	return append(extension, data...)
}

func quicClientHello(extensions ...[]byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	var extensionBytes []byte
	for _, extension := range extensions {
		extensionBytes = append(extensionBytes, extension...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensionBytes)))
	body = append(body, extensionBytes...)
	return append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func serverNameExtension(name string) []byte {
	data := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
	data = append(data, 0x00)
	data = binary.BigEndian.AppendUint16(data, uint16(len(name)))
	return quicTLSExtension(0, append(data, name...))
}

func sniffQUICWithin(t *testing.T, packet []byte) (adapter.InboundContext, error) {
	t.Helper()
	type result struct {
		metadata adapter.InboundContext
		err      error
		panicked any
	}
	done := make(chan result, 1)
	go func() {
		var current result
		defer func() {
			current.panicked = recover()
			done <- current
		}()
		current.err = sniff.QUICClientHello(context.Background(), &current.metadata, packet)
	}()
	select {
	case current := <-done:
		require.Nil(t, current.panicked, "sniffer panicked")
		return current.metadata, current.err
	case <-time.After(5 * time.Second):
		t.Fatal("sniffer did not return")
		return adapter.InboundContext{}, nil
	}
}

func TestSniffCraftedQUICInitialReadsServerName(t *testing.T) {
	t.Parallel()
	hello := quicClientHello(serverNameExtension("example.com"), quicTLSExtension(43, []byte{0x02, 0x03, 0x04}))
	metadata, err := sniffQUICWithin(t, sealQUICInitial(t, quicCryptoFrame(uint64(len(hello)), hello)))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolQUIC, metadata.Protocol)
	require.Equal(t, "example.com", metadata.Domain)
}

func TestSniffQUICCryptoFrameLongerThanPacket(t *testing.T) {
	t.Parallel()
	_, err := sniffQUICWithin(t, sealQUICInitial(t, quicCryptoFrame(4000, []byte{0x01, 0x00, 0x00, 0x00})))
	require.ErrorIs(t, err, os.ErrInvalid)
}

func TestSniffQUICEmptyCryptoFrame(t *testing.T) {
	t.Parallel()
	_, err := sniffQUICWithin(t, sealQUICInitial(t, quicCryptoFrame(0, nil)))
	require.ErrorIs(t, err, sniff.ErrNeedMoreData)
}

func TestSniffQUICClientHelloWithTruncatedExtensions(t *testing.T) {
	t.Parallel()
	for name, extension := range map[string][]byte{
		"supported_versions":   quicTLSExtension(43, []byte{0xfe}),
		"signature_algorithms": quicTLSExtension(13, []byte{0x00, 0x10}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			hello := quicClientHello(serverNameExtension("example.com"), extension)
			_, err := sniffQUICWithin(t, sealQUICInitial(t, quicCryptoFrame(uint64(len(hello)), hello)))
			require.ErrorIs(t, err, sniff.ErrNeedMoreData)
		})
	}
}
