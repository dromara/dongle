package hash

import (
	"errors"
	"strings"
	"testing"

	"gitee.com/golang-package/dongle/hash/md2"
	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestHasher_FromString(t *testing.T) {
	t.Run("normal string", func(t *testing.T) {
		hasher := NewHasher().FromString("hello")
		assert.Equal(t, []byte("hello"), hasher.src)
		assert.Equal(t, hasher, hasher.FromString("world"))
	})

	t.Run("empty string", func(t *testing.T) {
		hasher := NewHasher().FromString("")
		assert.Equal(t, []byte{}, hasher.src)
	})

	t.Run("unicode string", func(t *testing.T) {
		hasher := NewHasher().FromString("你好世界")
		assert.Equal(t, []byte("你好世界"), hasher.src)
	})
}

func TestHasher_FromBytes(t *testing.T) {
	t.Run("normal bytes", func(t *testing.T) {
		data := []byte("hello")
		hasher := NewHasher().FromBytes(data)
		assert.Equal(t, data, hasher.src)
		assert.Equal(t, hasher, hasher.FromBytes([]byte("world")))
	})

	t.Run("empty bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes([]byte{})
		assert.Equal(t, []byte{}, hasher.src)
	})

	t.Run("nil bytes", func(t *testing.T) {
		hasher := NewHasher().FromBytes(nil)
		assert.Nil(t, hasher.src)
	})

	t.Run("binary data", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02, 0x03}
		hasher := NewHasher().FromBytes(data)
		assert.Equal(t, data, hasher.src)
	})
}

func TestHasher_FromFile(t *testing.T) {
	t.Run("normal file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := NewHasher().FromFile(file)
		assert.Equal(t, file, hasher.reader)
		assert.Equal(t, hasher, hasher.FromFile(file))
	})

	t.Run("nil file", func(t *testing.T) {
		hasher := NewHasher().FromFile(nil)
		assert.Nil(t, hasher.reader)
	})
}

func TestHasher_WithKey(t *testing.T) {
	t.Run("normal key", func(t *testing.T) {
		key := []byte("secret")
		hasher := NewHasher().WithKey(key)
		assert.Equal(t, key, hasher.key)
		assert.Nil(t, hasher.Error)
		assert.Equal(t, hasher, hasher.WithKey(key))
	})

	t.Run("large key", func(t *testing.T) {
		key := strings.Repeat("secret", 100)
		hasher := NewHasher().WithKey([]byte(key))
		assert.Equal(t, []byte(key), hasher.key)
		assert.Nil(t, hasher.Error)
	})
}

func TestHasher_ToRawString(t *testing.T) {
	t.Run("normal data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte("hello")}
		result := hasher.ToRawString()
		assert.Equal(t, "hello", result)
	})

	t.Run("empty data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{}}
		result := hasher.ToRawString()
		assert.Equal(t, "", result)
	})

	t.Run("nil data", func(t *testing.T) {
		hasher := &Hasher{dst: nil}
		result := hasher.ToRawString()
		assert.Equal(t, "", result)
	})

	t.Run("unicode data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte("你好世界")}
		result := hasher.ToRawString()
		assert.Equal(t, "你好世界", result)
	})
}

func TestHasher_ToRawBytes(t *testing.T) {
	t.Run("normal data", func(t *testing.T) {
		data := []byte("hello")
		hasher := &Hasher{dst: data}
		result := hasher.ToRawBytes()
		assert.Equal(t, data, result)
	})

	t.Run("empty data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{}}
		result := hasher.ToRawBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("nil data", func(t *testing.T) {
		hasher := &Hasher{dst: nil}
		result := hasher.ToRawBytes()
		assert.Nil(t, result)
	})

	t.Run("binary data", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02, 0x03}
		hasher := &Hasher{dst: data}
		result := hasher.ToRawBytes()
		assert.Equal(t, data, result)
	})
}

func TestHasher_ToBase64String(t *testing.T) {
	t.Run("normal data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte("hello")}
		result := hasher.ToBase64String()
		assert.Equal(t, "aGVsbG8=", result)
	})

	t.Run("empty data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{}}
		result := hasher.ToBase64String()
		assert.Equal(t, "", result)
	})

	t.Run("nil data", func(t *testing.T) {
		hasher := &Hasher{dst: nil}
		result := hasher.ToBase64String()
		assert.Equal(t, "", result)
	})

	t.Run("binary data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{0x00, 0x01, 0x02, 0x03}}
		result := hasher.ToBase64String()
		assert.Equal(t, "AAECAw==", result)
	})
}

func TestHasher_ToBase64Bytes(t *testing.T) {
	t.Run("normal data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte("hello")}
		result := hasher.ToBase64Bytes()
		assert.Equal(t, []byte("aGVsbG8="), result)
	})

	t.Run("empty data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{}}
		result := hasher.ToBase64Bytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("nil data", func(t *testing.T) {
		hasher := &Hasher{dst: nil}
		result := hasher.ToBase64Bytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("binary data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{0x00, 0x01, 0x02, 0x03}}
		result := hasher.ToBase64Bytes()
		assert.Equal(t, []byte("AAECAw=="), result)
	})
}

func TestHasher_ToHexString(t *testing.T) {
	t.Run("normal data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte("hello")}
		result := hasher.ToHexString()
		assert.Equal(t, "68656c6c6f", result)
	})

	t.Run("empty data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{}}
		result := hasher.ToHexString()
		assert.Equal(t, "", result)
	})

	t.Run("nil data", func(t *testing.T) {
		hasher := &Hasher{dst: nil}
		result := hasher.ToHexString()
		assert.Equal(t, "", result)
	})

	t.Run("binary data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{0x00, 0x01, 0x02, 0x03}}
		result := hasher.ToHexString()
		assert.Equal(t, "00010203", result)
	})
}

func TestHasher_ToHexBytes(t *testing.T) {
	t.Run("normal data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte("hello")}
		result := hasher.ToHexBytes()
		assert.Equal(t, []byte("68656c6c6f"), result)
	})

	t.Run("empty data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{}}
		result := hasher.ToHexBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("nil data", func(t *testing.T) {
		hasher := &Hasher{dst: nil}
		result := hasher.ToHexBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("binary data", func(t *testing.T) {
		hasher := &Hasher{dst: []byte{0x00, 0x01, 0x02, 0x03}}
		result := hasher.ToHexBytes()
		assert.Equal(t, []byte("00010203"), result)
	})
}

func TestHasher_stream(t *testing.T) {
	t.Run("normal stream", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := &Hasher{reader: file}
		result, err := hasher.stream(md2.New)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 16, len(result)) // MD2 produces 16 bytes
	})

	t.Run("empty stream", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := &Hasher{reader: file}
		result, err := hasher.stream(md2.New)
		assert.Nil(t, err)
		assert.Equal(t, []byte{}, result)
	})

	t.Run("large stream", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		file := mock.NewFile([]byte(data), "large.txt")
		hasher := &Hasher{reader: file}
		result, err := hasher.stream(md2.New)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 16, len(result))
	})
}

func TestHasher_hmac(t *testing.T) {
	t.Run("hmac with source data", func(t *testing.T) {
		hasher := &Hasher{
			src: []byte("hello"),
			key: []byte("secret"),
		}
		result := hasher.hmac(md2.New)
		assert.Nil(t, result.Error)
		assert.NotNil(t, result.dst)
		assert.Equal(t, 16, len(result.dst)) // MD2 HMAC produces 16 bytes
	})

	t.Run("hmac with reader data", func(t *testing.T) {
		file := mock.NewFile([]byte("hello"), "test.txt")
		hasher := &Hasher{
			reader: file,
			key:    []byte("secret"),
		}
		result := hasher.hmac(md2.New)
		assert.Nil(t, result.Error)
		assert.NotNil(t, result.dst)
		assert.Equal(t, 16, len(result.dst))
	})

	t.Run("hmac with empty source and reader", func(t *testing.T) {
		hasher := &Hasher{
			key: []byte("secret"),
		}
		result := hasher.hmac(md2.New)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte{}, result.dst)
	})

	t.Run("hmac with empty reader", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		hasher := &Hasher{
			reader: file,
			key:    []byte("secret"),
		}
		result := hasher.hmac(md2.New)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte{}, result.dst)
	})

}

func TestHasher_Error(t *testing.T) {
	t.Run("multiple errors", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("first error")

		// WithKey should still work and set its own error
		result := hasher.WithKey([]byte{})
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "hmac: key cannot be empty")
	})

	t.Run("error propagation in hmac", func(t *testing.T) {
		hasher := NewHasher()
		hasher.Error = errors.New("existing error")

		result := hasher.hmac(md2.New)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

	t.Run("stream error handling", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("stream error"))
		hasher := &Hasher{reader: file}

		result, err := hasher.stream(md2.New)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "stream error")
		assert.Nil(t, result)
	})

	t.Run("WithKey empty key", func(t *testing.T) {
		hasher := NewHasher().WithKey([]byte{})
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
		assert.Nil(t, hasher.key)
	})

	t.Run("WithKey nil key", func(t *testing.T) {
		hasher := NewHasher().WithKey(nil)
		assert.NotNil(t, hasher.Error)
		assert.Contains(t, hasher.Error.Error(), "hmac: key cannot be empty")
		assert.Nil(t, hasher.key)
	})

	t.Run("stream with error", func(t *testing.T) {
		file := mock.NewErrorFile(errors.New("read error"))
		hasher := &Hasher{reader: file}
		result, err := hasher.stream(md2.New)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "read error")
		assert.Nil(t, result)
	})

	t.Run("hmac with empty key", func(t *testing.T) {
		hasher := &Hasher{
			src: []byte("hello"),
			key: []byte{},
		}
		result := hasher.hmac(md2.New)
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "key not set, please call WithKey() first")
	})

	t.Run("hmac with nil key", func(t *testing.T) {
		hasher := &Hasher{
			src: []byte("hello"),
			key: nil,
		}
		result := hasher.hmac(md2.New)
		assert.NotNil(t, result.Error)
		assert.Contains(t, result.Error.Error(), "key not set, please call WithKey() first")
	})

	t.Run("hmac with existing error", func(t *testing.T) {
		hasher := &Hasher{
			src:   []byte("hello"),
			key:   []byte("secret"),
			Error: errors.New("existing error"),
		}
		result := hasher.hmac(md2.New)
		assert.Equal(t, "existing error", result.Error.Error())
		assert.Nil(t, result.dst)
	})

}
