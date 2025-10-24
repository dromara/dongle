package coding

import (
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestEncoder_ByUnicode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello")
		result := encoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("hello"), result.dst)
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界")
		result := encoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte(`\u4f60\u597d\u4e16\u754c`), result.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte("hello"))
		result := encoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("hello"), result.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("")
		result := encoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{})
		result := encoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("encode from file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		defer file.Close()

		encoder := NewEncoder().FromFile(file)
		result := encoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("hello"), result.dst)
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := Encoder{Error: assert.AnError}
		result := encoder.ByUnicode()
		assert.Equal(t, assert.AnError, result.Error)
	})
}

func TestDecoder_ByUnicode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString("hello")
		result := decoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("hello"), result.dst)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(`\u4f60\u597d\u4e16\u754c`)
		result := decoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("你好世界"), result.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte("hello"))
		result := decoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("hello"), result.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("")
		result := decoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{})
		result := decoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Empty(t, result.dst)
	})

	t.Run("decode from file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		defer file.Close()

		decoder := NewDecoder().FromFile(file)
		result := decoder.ByUnicode()
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("hello"), result.dst)
	})

	t.Run("decode invalid unicode", func(t *testing.T) {
		decoder := NewDecoder().FromString(`\uZZZZ`)
		result := decoder.ByUnicode()
		assert.NotNil(t, result.Error)
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := Decoder{Error: assert.AnError}
		result := decoder.ByUnicode()
		assert.Equal(t, assert.AnError, result.Error)
	})
}

func TestUnicodeRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"simple", "hello"},
		{"unicode", "你好世界"},
		{"mixed", "hello 世界"},
		{"special", "hello\nworld\t"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoder := NewEncoder().FromString(tc.data)
			encoded := encoder.ByUnicode()
			assert.Nil(t, encoded.Error)

			// Decode
			decoder := NewDecoder().FromBytes(encoded.dst)
			decoded := decoder.ByUnicode()
			assert.Nil(t, decoded.Error)
			assert.Equal(t, tc.data, decoded.ToString())
		})
	}
}
