package vmess

import (
	"bytes"
	"io"
	"testing"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"

	"golang.org/x/crypto/sha3"
)

type lengthChunkWriter interface {
	io.Writer
	WriteBuffer(buffer *buf.Buffer) error
}

type lengthChunkPair struct {
	name   string
	writer func(upstream io.Writer) lengthChunkWriter
	reader func(upstream io.Reader) io.Reader
}

func seededShake(seed string) sha3.ShakeHash {
	shake := sha3.NewShake128()
	common.Must1(shake.Write([]byte(seed)))
	return shake
}

func lengthChunkPairs() []lengthChunkPair {
	key := bytes.Repeat([]byte{0x42}, 16)
	nonce := bytes.Repeat([]byte{0x24}, 16)
	return []lengthChunkPair{
		{
			name: "stream",
			writer: func(upstream io.Writer) lengthChunkWriter {
				return NewStreamChunkWriter(upstream, nil, nil)
			},
			reader: func(upstream io.Reader) io.Reader {
				return NewStreamChunkReader(upstream, nil, nil)
			},
		},
		{
			name: "stream masked and padded",
			writer: func(upstream io.Writer) lengthChunkWriter {
				return NewStreamChunkWriter(upstream, seededShake("mask"), seededShake("pad"))
			},
			reader: func(upstream io.Reader) io.Reader {
				return NewStreamChunkReader(upstream, seededShake("mask"), seededShake("pad"))
			},
		},
		{
			name: "aes-128-gcm length",
			writer: func(upstream io.Writer) lengthChunkWriter {
				return NewAes128GcmChunkWriter(upstream, key, nonce, nil)
			},
			reader: func(upstream io.Reader) io.Reader {
				return NewAes128GcmChunkReader(upstream, key, nonce, nil)
			},
		},
		{
			name: "chacha20-poly1305 length padded",
			writer: func(upstream io.Writer) lengthChunkWriter {
				return NewChacha20Poly1305ChunkWriter(upstream, key, nonce, seededShake("pad"))
			},
			reader: func(upstream io.Reader) io.Reader {
				return NewChacha20Poly1305ChunkReader(upstream, key, nonce, seededShake("pad"))
			},
		},
	}
}

func chunkBuffer(payload []byte) *buf.Buffer {
	buffer := buf.NewSize(2 + CipherOverhead + len(payload) + MaxPaddingSize)
	buffer.Resize(2+CipherOverhead, 0)
	common.Must1(buffer.Write(payload))
	return buffer
}

func readAfterEmptyChunkWrite(t *testing.T, pair lengthChunkPair, wire *bytes.Buffer, emptyFrame int, payload []byte) {
	t.Helper()
	if emptyFrame != 0 {
		t.Errorf("the empty write put %d bytes on the wire, want none", emptyFrame)
	}
	got := make([]byte, 1024)
	n, err := pair.reader(wire).Read(got)
	if err != nil {
		t.Fatalf("the peer read %v after an empty write, want %q", err, payload)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Fatalf("the peer read %q after an empty write, want %q", got[:n], payload)
	}
}

func TestEmptyChunkWriteDoesNotEndThePeerStream(t *testing.T) {
	payload := []byte("data after the empty write")
	for _, pair := range lengthChunkPairs() {
		t.Run(pair.name+"/Write", func(t *testing.T) {
			var wire bytes.Buffer
			writer := pair.writer(&wire)
			n, err := writer.Write(nil)
			if err != nil || n != 0 {
				t.Fatalf("empty Write returned n=%d err=%v, want 0 and nil", n, err)
			}
			emptyFrame := wire.Len()
			if _, err = writer.Write(payload); err != nil {
				t.Fatal(err)
			}
			readAfterEmptyChunkWrite(t, pair, &wire, emptyFrame, payload)
		})
		t.Run(pair.name+"/WriteBuffer", func(t *testing.T) {
			var wire bytes.Buffer
			writer := pair.writer(&wire)
			empty := chunkBuffer(nil)
			if err := writer.WriteBuffer(empty); err != nil {
				t.Fatalf("empty WriteBuffer returned %v, want nil", err)
			}
			if empty.Cap() != 0 {
				t.Fatalf("empty WriteBuffer kept its buffer (cap %d), want it released", empty.Cap())
			}
			emptyFrame := wire.Len()
			if err := writer.WriteBuffer(chunkBuffer(payload)); err != nil {
				t.Fatal(err)
			}
			readAfterEmptyChunkWrite(t, pair, &wire, emptyFrame, payload)
		})
	}
}
