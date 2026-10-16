package base85

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestStdDecoder_DecodeZeroShortcut verifies that data encoded with the ASCII85
// "z" shortcut for an all-zero group round-trips back to the original bytes.
func TestStdDecoder_DecodeZeroShortcut(t *testing.T) {
	tests := []struct {
		name string
		src  []byte
	}{
		{"zero group only", []byte{0, 0, 0, 0}},
		{"zero group then partial", []byte{0, 0, 0, 0, 0}},
		{"zero group then one byte", []byte{0, 0, 0, 0, 'a'}},
		{"two zero groups", []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{"data then zero group", []byte{'a', 'b', 'c', 'd', 0, 0, 0, 0}},
		{"zero group then data", []byte{0, 0, 0, 0, 'a', 'b', 'c', 'd'}},
		{"four zero groups", make([]byte, 16)},
		{"four zero groups then data", append(make([]byte, 16), 'a', 'b', 'c', 'd')},
		{"data then four zero groups then partial", append(append([]byte{'a', 'b', 'c', 'd'}, make([]byte, 16)...), 'e')},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := NewStdEncoder().Encode(tt.src)
			decoded, err := NewStdDecoder().Decode(encoded)
			assert.Nil(t, err)
			assert.Equal(t, tt.src, decoded)
		})
	}
}

// TestStreamDecoder_DecodeZeroShortcut is the streaming counterpart.
func TestStreamDecoder_DecodeZeroShortcut(t *testing.T) {
	src := []byte{0, 0, 0, 0, 0}
	var buf bytes.Buffer
	encoder := NewStreamEncoder(&buf)
	_, err := encoder.Write(src)
	assert.Nil(t, err)
	assert.Nil(t, encoder.Close())

	out := make([]byte, 32)
	n, _ := NewStreamDecoder(bytes.NewReader(buf.Bytes())).Read(out)
	assert.Equal(t, src, out[:n])
}

// TestStreamDecoder_DecodeZeroShortcutPadding checks that 'z' shortcuts are not
// counted when padding a trailing partial group.
func TestStreamDecoder_DecodeZeroShortcutPadding(t *testing.T) {
	src := append(make([]byte, 16), 'a', 'b', 'c', 'd')
	var buf bytes.Buffer
	encoder := NewStreamEncoder(&buf)
	_, err := encoder.Write(src)
	assert.Nil(t, err)
	assert.Nil(t, encoder.Close())

	out := make([]byte, 32)
	n, err := NewStreamDecoder(bytes.NewReader(buf.Bytes())).Read(out)
	assert.Nil(t, err)
	assert.Equal(t, src, out[:n])
}
