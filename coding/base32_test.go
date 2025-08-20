package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestEncoder_ByBase32(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase32()
		assert.Nil(t, encoder.Error)
		// Python: base64.b32encode(b"hello world").decode() = "NBSWY3DPEB3W64TMMQ======"
		assert.Equal(t, []byte("NBSWY3DPEB3W64TMMQ======"), encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase32()
		assert.Nil(t, encoder.Error)
		// Python: base64.b32encode(bytes([0x00, 0x01, 0x02, 0x03])).decode() = "AAAQEAY="
		assert.Equal(t, []byte("AAAQEAY="), encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase32()
		assert.Nil(t, encoder.Error)
		// Python: base64.b32encode(b"hello world").decode() = "NBSWY3DPEB3W64TMMQ======"
		assert.Equal(t, []byte("NBSWY3DPEB3W64TMMQ======"), encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase32()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase32()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello world").ByBase32()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase32()
		assert.Nil(t, encoder.Error)
		// Python: base64.b32encode("你好世界".encode('utf-8')).decode() = "4S62BZNFXXSLRFXHSWGA===="
		assert.Equal(t, []byte("4S62BZNFXXSLRFXHSWGA===="), encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase32()
		assert.Nil(t, encoder.Error)
		// For large data, test round-trip instead of exact value
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase32()
		assert.Nil(t, encoder.Error)
		// Python: base64.b32encode(bytes([0x41])).decode() = "IE======"
		assert.Equal(t, []byte("IE======"), encoder.dst)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase32()
		assert.Nil(t, encoder.Error)
		// Python: base64.b32encode(bytes([0x41, 0x42])).decode() = "IFBA===="
		assert.Equal(t, []byte("IFBA===="), encoder.dst)
	})

	t.Run("encode three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase32()
		assert.Nil(t, encoder.Error)
		// Python: base64.b32encode(bytes([0x41, 0x42, 0x43])).decode() = "IFBEG==="
		assert.Equal(t, []byte("IFBEG==="), encoder.dst)
	})

	t.Run("encode zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase32()
		assert.Nil(t, encoder.Error)
		// Python: base64.b32encode(bytes([0x00, 0x00, 0x00, 0x00])).decode() = "AAAAAAA="
		assert.Equal(t, []byte("AAAAAAA="), encoder.dst)
	})

	t.Run("encode max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase32()
		assert.Nil(t, encoder.Error)
		// Python: base64.b32encode(bytes([0xFF, 0xFF, 0xFF, 0xFF])).decode() = "777777Y="
		assert.Equal(t, []byte("777777Y="), encoder.dst)
	})
}

func TestDecoder_ByBase32(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase32()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase32()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase32()
		assert.Nil(t, encoder.Error)

		// Then decode with file
		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase32()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("NBSWY3DPEB3W64TMMQ======").ByBase32()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decode invalid base32", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase32()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		// First encode unicode data
		encoder := NewEncoder().FromString("你好世界").ByBase32()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("你好世界"), decoder.dst)
	})

	t.Run("decode single byte encoded", func(t *testing.T) {
		// Encode single byte
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase32()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.dst)
	})

	t.Run("decode two bytes encoded", func(t *testing.T) {
		// Encode two bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase32()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.dst)
	})

	t.Run("decode three bytes encoded", func(t *testing.T) {
		// Encode three bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase32()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.dst)
	})

	t.Run("decode zero bytes encoded", func(t *testing.T) {
		// Encode zero bytes
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase32()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.dst)
	})

	t.Run("decode max bytes encoded", func(t *testing.T) {
		// Encode max bytes
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase32()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.dst)
	})
}

func TestError_ByBase32(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByBase32()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByBase32()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder invalid character", func(t *testing.T) {
		// Create data with invalid base32 characters
		invalidData := []byte("invalid!") // '!' is not a valid base32 character
		decoder := NewDecoder().FromBytes(invalidData).ByBase32()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "illegal data")
	})

	t.Run("decoder corrupt data", func(t *testing.T) {
		// Create corrupt base32 data with invalid characters
		corruptData := []byte("AB!") // '!' is not a valid base32 character
		decoder := NewDecoder().FromBytes(corruptData).ByBase32()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "illegal data")
	})

	t.Run("decoder invalid padding", func(t *testing.T) {
		// Create invalid padding data
		invalidPadding := []byte("NBSWY3DPEB3W64TMMQ=====!") // Invalid padding with extra character
		decoder := NewDecoder().FromBytes(invalidPadding).ByBase32()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "illegal data")
	})

	t.Run("decoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase32()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("encoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase32()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})
}

func TestEncoder_ByBase32Hex(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world").ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// Base32Hex encoding of "hello world" = "D1IMOR3F41RMUSJCCG======"
		assert.Equal(t, []byte("D1IMOR3F41RMUSJCCG======"), encoder.dst)
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// Base32Hex encoding of [0x00, 0x01, 0x02, 0x03] = "000G40O="
		assert.Equal(t, []byte("000G40O="), encoder.dst)
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Nil(t, encoder.dst)
	})

	t.Run("encode with file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// Base32Hex encoding of "hello world" = "D1IMOR3F41RMUSJCCG======"
		assert.Equal(t, []byte("D1IMOR3F41RMUSJCCG======"), encoder.dst)
	})

	t.Run("encode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, []byte{}, encoder.dst)
	})

	t.Run("encode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase32Hex()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode with existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("hello world").ByBase32Hex()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("encode unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界").ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// Base32Hex encoding of "你好世界" = "SIUQ1PD5NNIBH5N7IM60===="
		assert.Equal(t, []byte("SIUQ1PD5NNIBH5N7IM60===="), encoder.dst)
	})

	t.Run("encode large data", func(t *testing.T) {
		largeData := strings.Repeat("Hello, World! ", 100)
		encoder := NewEncoder().FromString(largeData).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// For large data, test round-trip instead of exact value
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(largeData), decoder.dst)
	})

	t.Run("encode single byte", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// Base32Hex encoding of byte 0x41 = "84======"
		assert.Equal(t, []byte("84======"), encoder.dst)
	})

	t.Run("encode two bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// Base32Hex encoding of bytes [0x41, 0x42] = "8510===="
		assert.Equal(t, []byte("8510===="), encoder.dst)
	})

	t.Run("encode three bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// Base32Hex encoding of bytes [0x41, 0x42, 0x43] = "85146==="
		assert.Equal(t, []byte("85146==="), encoder.dst)
	})

	t.Run("encode zero bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// Base32Hex encoding of zero bytes = "0000000="
		assert.Equal(t, []byte("0000000="), encoder.dst)
	})

	t.Run("encode max bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase32Hex()
		assert.Nil(t, encoder.Error)
		// Base32Hex encoding of max bytes = "VVVVVVO="
		assert.Equal(t, []byte("VVVVVVO="), encoder.dst)
	})
}

func TestDecoder_ByBase32Hex(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase32Hex()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode bytes", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase32Hex()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, decoder.dst)
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Nil(t, decoder.dst)
	})

	t.Run("decode with file", func(t *testing.T) {
		// First encode some data
		encoder := NewEncoder().FromString("hello world").ByBase32Hex()
		assert.Nil(t, encoder.Error)

		// Then decode with file
		file := mock.NewFile(encoder.dst, "test.txt")
		decoder := NewDecoder().FromFile(file).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("hello world"), decoder.dst)
	})

	t.Run("decode with empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{}, decoder.dst)
	})

	t.Run("decode with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase32Hex()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("D1IMOR3F41RMUSJCCG======").ByBase32Hex()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "existing error", result.Error.Error())
	})

	t.Run("decode invalid base32hex", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid!").ByBase32Hex()
		assert.Error(t, decoder.Error)
	})

	t.Run("decode unicode string", func(t *testing.T) {
		// First encode unicode data
		encoder := NewEncoder().FromString("你好世界").ByBase32Hex()
		assert.Nil(t, encoder.Error)

		// Then decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte("你好世界"), decoder.dst)
	})

	t.Run("decode single byte encoded", func(t *testing.T) {
		// Encode single byte
		encoder := NewEncoder().FromBytes([]byte{0x41}).ByBase32Hex()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41}, decoder.dst)
	})

	t.Run("decode two bytes encoded", func(t *testing.T) {
		// Encode two bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42}).ByBase32Hex()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42}, decoder.dst)
	})

	t.Run("decode three bytes encoded", func(t *testing.T) {
		// Encode three bytes
		encoder := NewEncoder().FromBytes([]byte{0x41, 0x42, 0x43}).ByBase32Hex()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x41, 0x42, 0x43}, decoder.dst)
	})

	t.Run("decode zero bytes encoded", func(t *testing.T) {
		// Encode zero bytes
		encoder := NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase32Hex()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, decoder.dst)
	})

	t.Run("decode max bytes encoded", func(t *testing.T) {
		// Encode max bytes
		encoder := NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase32Hex()
		assert.Nil(t, encoder.Error)

		// Decode it
		decoder := NewDecoder().FromBytes(encoder.dst).ByBase32Hex()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0xFF}, decoder.dst)
	})
}

func TestError_ByBase32Hex(t *testing.T) {
	t.Run("encoder error propagation", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("test error")

		result := encoder.ByBase32Hex()
		assert.Equal(t, encoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder error propagation", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("test error")

		result := decoder.ByBase32Hex()
		assert.Equal(t, decoder, result)
		assert.Equal(t, "test error", result.Error.Error())
	})

	t.Run("decoder invalid character", func(t *testing.T) {
		// Create data with invalid base32hex characters
		invalidData := []byte("invalid!") // '!' is not a valid base32hex character
		decoder := NewDecoder().FromBytes(invalidData).ByBase32Hex()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "illegal data")
	})

	t.Run("decoder corrupt data", func(t *testing.T) {
		// Create corrupt base32hex data with invalid characters
		corruptData := []byte("AB!") // '!' is not a valid base32hex character
		decoder := NewDecoder().FromBytes(corruptData).ByBase32Hex()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "illegal data")
	})

	t.Run("decoder invalid padding", func(t *testing.T) {
		// Create invalid padding data with wrong padding length
		invalidPadding := []byte("D1IMOR3F41RMUSJCCG==") // Invalid padding (should be 6 = signs)
		decoder := NewDecoder().FromBytes(invalidPadding).ByBase32Hex()
		assert.Error(t, decoder.Error)
	})

	t.Run("decoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByBase32Hex()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("encoder with error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByBase32Hex()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})
}
