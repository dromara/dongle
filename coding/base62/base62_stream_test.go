package base62

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The stream encoder and decoder must produce the same result as encoding or
// decoding the whole input at once, because base62 treats the input as one number.
func TestStream_MatchesStd(t *testing.T) {
	src := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 30)
	want := NewStdEncoder().Encode(src)
	assert.Greater(t, len(want), 1024)

	t.Run("encode in several writes", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		for i := 0; i < len(src); i += 5 {
			end := i + 5
			if end > len(src) {
				end = len(src)
			}
			_, err := encoder.Write(src[i:end])
			assert.Nil(t, err)
		}
		assert.Nil(t, encoder.Close())
		assert.Equal(t, string(want), buf.String())
	})

	t.Run("encode in one write", func(t *testing.T) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		_, err := encoder.Write(src)
		assert.Nil(t, err)
		assert.Nil(t, encoder.Close())
		assert.Equal(t, string(want), buf.String())
	})

	t.Run("decode more than one read buffer", func(t *testing.T) {
		got, err := io.ReadAll(NewStreamDecoder(bytes.NewReader(want)))
		assert.Nil(t, err)
		assert.Equal(t, src, got)
	})
}

// Retaining a drained decoder must not keep the full decoded payload alive.
func TestStreamDecoder_ReleasesDrainedBuffer(t *testing.T) {
	src := bytes.Repeat([]byte("payload"), 300)
	encoded := NewStdEncoder().Encode(src)
	for _, size := range []int{17, len(src) * 2} {
		d := NewStreamDecoder(bytes.NewReader(encoded)).(*StreamDecoder)
		var got []byte
		buf := make([]byte, size)
		for {
			n, err := d.Read(buf)
			got = append(got, buf[:n]...)
			if len(got) == len(src) {
				if d.buffer != nil {
					t.Fatal("drained decoder retains decoded input")
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		assert.Equal(t, src, got)
	}
}

// The whole-stream path must remain practical for inputs larger than a chunk.
func TestStreamDecoder_LargeInput(t *testing.T) {
	src := bytes.Repeat([]byte("large-file-payload"), 4096)
	encoded := NewStdEncoder().Encode(src)
	got, err := io.ReadAll(NewStreamDecoder(bytes.NewReader(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, src, got)
}
