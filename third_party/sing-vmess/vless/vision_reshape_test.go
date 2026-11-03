package vless

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

const visionReshapeLimit = 8192 - 21

func reshapeInput(size int, recordStarts ...int) []byte {
	input := make([]byte, size)
	for i := range input {
		input[i] = byte(i%251) | 0x80
	}
	for _, start := range recordStarts {
		copy(input[start:], tlsApplicationDataStart)
	}
	return input
}

func TestReshapeBufferKeepsEveryPieceWithinTheVisionLimit(t *testing.T) {
	everyFiveThousand := make([]int, 0, 14)
	for start := 0; start < 70000; start += 5000 {
		everyFiveThousand = append(everyFiveThousand, start)
	}
	testCases := []struct {
		name  string
		input []byte
	}{
		{"70000 bytes without a record header", reshapeInput(70000)},
		{"record header past the limit", reshapeInput(20000, 15000)},
		{"record header near the start of 70000 bytes", reshapeInput(70000, 100)},
		{"record headers every 5000 bytes", reshapeInput(70000, everyFiveThousand...)},
		{"one byte under the limit", reshapeInput(visionReshapeLimit - 1)},
		{"exactly the limit", reshapeInput(visionReshapeLimit)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			pieces := reshapeBuffer(testCase.input)
			lengths := make([]int, 0, len(pieces))
			var joined []byte
			for _, piece := range pieces {
				lengths = append(lengths, piece.Len())
				joined = append(joined, piece.Bytes()...)
			}
			for _, length := range lengths {
				if length > visionReshapeLimit {
					t.Fatalf("reshapeBuffer(%d bytes) gave pieces %v, a piece is over the %d byte limit", len(testCase.input), lengths, visionReshapeLimit)
				}
			}
			if !bytes.Equal(joined, testCase.input) {
				t.Fatalf("reshapeBuffer(%d bytes) pieces %v do not join back to the input", len(testCase.input), lengths)
			}
		})
	}
}

func TestPaddedLargeWriteSurvivesTheVisionFraming(t *testing.T) {
	userUUID := [16]byte{0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c}
	writer := &VisionConn{logger: logger.NOP(), userUUID: userUUID, writeUUID: true}
	reader := &VisionConn{logger: logger.NOP(), userUUID: userUUID, remainingContent: -1, remainingPadding: -1}
	input := reshapeInput(70000)
	var wire []byte
	for _, piece := range reshapeBuffer(input) {
		frame := writer.padding(piece, commandPaddingContinue)
		wire = append(wire, frame.Bytes()...)
		frame.Release()
	}
	got := unPadded(t, reader, exactSlice(wire))
	if !bytes.Equal(got, input) {
		t.Fatalf("a padded 70000 byte write unpadded to %d bytes, want the original %d bytes", len(got), len(input))
	}
}
