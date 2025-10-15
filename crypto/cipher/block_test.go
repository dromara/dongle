package cipher

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockBlock is a mock implementation of cipher.Block for testing
type mockBlock struct {
	blockSize int
	encrypt   func(dst, src []byte)
	decrypt   func(dst, src []byte)
}

func (m *mockBlock) BlockSize() int { return m.blockSize }
func (m *mockBlock) Encrypt(dst, src []byte) {
	if m.encrypt != nil {
		m.encrypt(dst, src)
	} else {
		copy(dst, src)
	}
}
func (m *mockBlock) Decrypt(dst, src []byte) {
	if m.decrypt != nil {
		m.decrypt(dst, src)
	} else {
		copy(dst, src)
	}
}

func TestBlockModes(t *testing.T) {
	t.Run("BlockMode constants", func(t *testing.T) {
		assert.Equal(t, BlockMode("CBC"), CBC)
		assert.Equal(t, BlockMode("ECB"), ECB)
		assert.Equal(t, BlockMode("CTR"), CTR)
		assert.Equal(t, BlockMode("GCM"), GCM)
		assert.Equal(t, BlockMode("CFB"), CFB)
		assert.Equal(t, BlockMode("OFB"), OFB)
	})

	t.Run("BlockMode string conversion", func(t *testing.T) {
		assert.Equal(t, "CBC", string(CBC))
		assert.Equal(t, "ECB", string(ECB))
		assert.Equal(t, "CTR", string(CTR))
		assert.Equal(t, "GCM", string(GCM))
		assert.Equal(t, "CFB", string(CFB))
		assert.Equal(t, "OFB", string(OFB))
	})
}

func TestNewCBCEncrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	src := make([]byte, 32) // 2 blocks

	t.Run("successful encryption", func(t *testing.T) {
		result, err := NewCBCEncrypter(src, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
		assert.NotEqual(t, src, result) // Should be encrypted
	})

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewCBCEncrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})

	t.Run("invalid IV length", func(t *testing.T) {
		invalidIV := make([]byte, 8) // Wrong size
		result, err := NewCBCEncrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 8 must equal block size 16")
	})

	t.Run("invalid source length", func(t *testing.T) {
		invalidSrc := make([]byte, 17) // Not multiple of block size
		result, err := NewCBCEncrypter(invalidSrc, iv, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidSrcError{}, err)
		assert.Contains(t, err.Error(), "src length 17 must be a multiple of block size 16")
	})
}

func TestNewCBCDecrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	src := make([]byte, 32) // 2 blocks

	t.Run("successful decryption", func(t *testing.T) {
		result, err := NewCBCDecrypter(src, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
	})

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewCBCDecrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})

	t.Run("invalid IV length", func(t *testing.T) {
		invalidIV := make([]byte, 8) // Wrong size
		result, err := NewCBCDecrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 8 must equal block size 16")
	})

	t.Run("invalid source length", func(t *testing.T) {
		invalidSrc := make([]byte, 17) // Not multiple of block size
		result, err := NewCBCDecrypter(invalidSrc, iv, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidSrcError{}, err)
		assert.Contains(t, err.Error(), "src length 17 must be a multiple of block size 16")
	})
}

func TestNewCTREncrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	src := make([]byte, 25) // Any length is fine for CTR

	t.Run("successful encryption with 16-byte IV", func(t *testing.T) {
		result, err := NewCTREncrypter(src, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
		assert.NotEqual(t, src, result) // Should be encrypted
	})

	t.Run("successful encryption with 12-byte nonce", func(t *testing.T) {
		nonce := make([]byte, 12)
		result, err := NewCTREncrypter(src, nonce, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
		assert.NotEqual(t, src, result) // Should be encrypted
	})

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewCTREncrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})
}

func TestNewCTRDecrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	src := make([]byte, 25) // Any length is fine for CTR

	t.Run("successful decryption with 16-byte IV", func(t *testing.T) {
		result, err := NewCTRDecrypter(src, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
	})

	t.Run("successful decryption with 12-byte nonce", func(t *testing.T) {
		nonce := make([]byte, 12)
		result, err := NewCTRDecrypter(src, nonce, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
	})

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewCTRDecrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})
}

func TestNewECBEncrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	src := make([]byte, 32) // 2 blocks

	t.Run("successful encryption", func(t *testing.T) {
		result, err := NewECBEncrypter(src, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
		assert.NotEqual(t, src, result) // Should be encrypted
	})

	t.Run("invalid source length", func(t *testing.T) {
		invalidSrc := make([]byte, 17) // Not multiple of block size
		result, err := NewECBEncrypter(invalidSrc, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidSrcError{}, err)
		assert.Contains(t, err.Error(), "src length 17 must be a multiple of block size 16")
	})

	t.Run("single block encryption", func(t *testing.T) {
		singleBlock := make([]byte, 16)
		result, err := NewECBEncrypter(singleBlock, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(singleBlock), len(result))
		assert.NotEqual(t, singleBlock, result) // Should be encrypted
	})
}

func TestNewECBDecrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	src := make([]byte, 32) // 2 blocks

	t.Run("successful decryption", func(t *testing.T) {
		result, err := NewECBDecrypter(src, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
	})

	t.Run("invalid source length", func(t *testing.T) {
		invalidSrc := make([]byte, 17) // Not multiple of block size
		result, err := NewECBDecrypter(invalidSrc, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidSrcError{}, err)
		assert.Contains(t, err.Error(), "src length 17 must be a multiple of block size 16")
	})

	t.Run("single block decryption", func(t *testing.T) {
		singleBlock := make([]byte, 16)
		result, err := NewECBDecrypter(singleBlock, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(singleBlock), len(result))
	})
}

func TestNewGCMEncrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	nonce := make([]byte, 12)
	aad := []byte("additional data")
	src := make([]byte, 25) // Any length is fine for GCM

	t.Run("successful encryption", func(t *testing.T) {
		result, err := NewGCMEncrypter(src, nonce, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.NotEqual(t, src, result)        // Should be encrypted
		assert.True(t, len(result) > len(src)) // GCM adds authentication tag
	})

	t.Run("successful encryption without AAD", func(t *testing.T) {
		result, err := NewGCMEncrypter(src, nonce, nil, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.NotEqual(t, src, result) // Should be encrypted
	})

	t.Run("empty nonce", func(t *testing.T) {
		result, err := NewGCMEncrypter(src, []byte{}, aad, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyNonceError{}, err)
		assert.Contains(t, err.Error(), "nonce cannot be empty")
	})

	t.Run("empty source", func(t *testing.T) {
		result, err := NewGCMEncrypter([]byte{}, nonce, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.True(t, len(result) > 0) // GCM adds authentication tag even for empty data
	})
}

func TestNewGCMDecrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	nonce := make([]byte, 12)
	aad := []byte("additional data")

	t.Run("successful decryption", func(t *testing.T) {
		// First encrypt some data
		encrypted, err := NewGCMEncrypter([]byte("test data"), nonce, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)

		// Then decrypt it
		result, err := NewGCMDecrypter(encrypted, nonce, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, []byte("test data"), result)
	})

	t.Run("successful decryption without AAD", func(t *testing.T) {
		// First encrypt some data without AAD
		encrypted, err := NewGCMEncrypter([]byte("test data"), nonce, nil, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)

		// Then decrypt it without AAD
		result, err := NewGCMDecrypter(encrypted, nonce, nil, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, []byte("test data"), result)
	})

	t.Run("empty nonce", func(t *testing.T) {
		result, err := NewGCMDecrypter([]byte("test"), []byte{}, aad, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyNonceError{}, err)
		assert.Contains(t, err.Error(), "nonce cannot be empty")
	})

	t.Run("decryption with wrong AAD", func(t *testing.T) {
		// First encrypt some data with AAD
		encrypted, err := NewGCMEncrypter([]byte("test data"), nonce, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)

		// Then decrypt it with wrong AAD
		wrongAAD := []byte("wrong additional data")
		result, err := NewGCMDecrypter(encrypted, nonce, wrongAAD, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, CreateCipherError{}, err)
		assert.Contains(t, err.Error(), "failed to create cipher")
	})

	t.Run("GCM cipher creation error", func(t *testing.T) {
		// Create a mock block with non-128-bit block size to cause GCM creation to fail
		mockBlock := &mockBlock{
			blockSize: 24, // Non-128-bit block size will cause GCM creation to fail
			encrypt: func(dst, src []byte) {
				copy(dst, src)
			},
			decrypt: func(dst, src []byte) {
				copy(dst, src)
			},
		}

		// Test encryption with failing GCM creation
		result, err := NewGCMEncrypter([]byte("test data"), nonce, aad, mockBlock)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, CreateCipherError{}, err)
		assert.Contains(t, err.Error(), "failed to create cipher")

		// Test decryption with failing GCM creation
		result, err = NewGCMDecrypter([]byte("test data"), nonce, aad, mockBlock)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, CreateCipherError{}, err)
		assert.Contains(t, err.Error(), "failed to create cipher")
	})
}

func TestNewCFBEncrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	src := make([]byte, 25) // Any length is fine for CFB

	t.Run("successful encryption", func(t *testing.T) {
		result, err := NewCFBEncrypter(src, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
		assert.NotEqual(t, src, result) // Should be encrypted
	})

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewCFBEncrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})

	t.Run("invalid IV length", func(t *testing.T) {
		invalidIV := make([]byte, 8) // Wrong size
		result, err := NewCFBEncrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 8 must equal block size 16")
	})

	t.Run("empty source", func(t *testing.T) {
		result, err := NewCFBEncrypter([]byte{}, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 0, len(result))
	})
}

func TestNewCFBDecrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	src := make([]byte, 25) // Any length is fine for CFB

	t.Run("successful decryption", func(t *testing.T) {
		result, err := NewCFBDecrypter(src, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
	})

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewCFBDecrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})

	t.Run("invalid IV length", func(t *testing.T) {
		invalidIV := make([]byte, 8) // Wrong size
		result, err := NewCFBDecrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 8 must equal block size 16")
	})

	t.Run("empty source", func(t *testing.T) {
		result, err := NewCFBDecrypter([]byte{}, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 0, len(result))
	})
}

func TestNewOFBEncrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	src := make([]byte, 25) // Any length is fine for OFB

	t.Run("successful encryption", func(t *testing.T) {
		result, err := NewOFBEncrypter(src, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
		assert.NotEqual(t, src, result) // Should be encrypted
	})

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewOFBEncrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})

	t.Run("invalid IV length", func(t *testing.T) {
		invalidIV := make([]byte, 8) // Wrong size
		result, err := NewOFBEncrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 8 must equal block size 16")
	})

	t.Run("empty source", func(t *testing.T) {
		result, err := NewOFBEncrypter([]byte{}, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 0, len(result))
	})
}

func TestNewOFBDecrypter(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)
	src := make([]byte, 25) // Any length is fine for OFB

	t.Run("successful decryption", func(t *testing.T) {
		result, err := NewOFBDecrypter(src, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(src), len(result))
	})

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewOFBDecrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})

	t.Run("invalid IV length", func(t *testing.T) {
		invalidIV := make([]byte, 8) // Wrong size
		result, err := NewOFBDecrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 8 must equal block size 16")
	})

	t.Run("empty source", func(t *testing.T) {
		result, err := NewOFBDecrypter([]byte{}, iv, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 0, len(result))
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("InvalidSrcError", func(t *testing.T) {
		err := InvalidSrcError{
			mode: CBC,
			src:  []byte("test"),
			size: 16,
		}
		msg := err.Error()
		assert.Contains(t, msg, "CBC")
		assert.Contains(t, msg, "src length 4")
		assert.Contains(t, msg, "block size 16")
	})

	t.Run("EmptyIVError", func(t *testing.T) {
		err := EmptyIVError{mode: CTR}
		msg := err.Error()
		assert.Contains(t, msg, "CTR")
		assert.Contains(t, msg, "iv cannot be empty")
	})

	t.Run("InvalidIVError", func(t *testing.T) {
		err := InvalidIVError{
			mode: CFB,
			iv:   []byte("test"),
			size: 16,
		}
		msg := err.Error()
		assert.Contains(t, msg, "CFB")
		assert.Contains(t, msg, "iv length 4")
		assert.Contains(t, msg, "block size 16")
	})

	t.Run("EmptyNonceError", func(t *testing.T) {
		err := EmptyNonceError{mode: GCM}
		msg := err.Error()
		assert.Contains(t, msg, "GCM")
		assert.Contains(t, msg, "nonce cannot be empty")
	})

	t.Run("CreateCipherError", func(t *testing.T) {
		underlyingErr := assert.AnError
		err := CreateCipherError{
			mode: ECB,
			err:  underlyingErr,
		}
		msg := err.Error()
		assert.Contains(t, msg, "ECB")
		assert.Contains(t, msg, "failed to create cipher")
		assert.Contains(t, msg, underlyingErr.Error())
	})
}

func TestMockBlock(t *testing.T) {
	t.Run("mock block functionality", func(t *testing.T) {
		mock := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simulate encryption by adding 1 to each byte
				for i := range src {
					dst[i] = src[i] + 1
				}
			},
			decrypt: func(dst, src []byte) {
				// Simulate decryption by subtracting 1 from each byte
				for i := range src {
					dst[i] = src[i] - 1
				}
			},
		}

		assert.Equal(t, 16, mock.BlockSize())

		src := []byte("test data")
		dst := make([]byte, len(src))
		mock.Encrypt(dst, src)
		assert.NotEqual(t, src, dst)

		decrypted := make([]byte, len(dst))
		mock.Decrypt(decrypted, dst)
		assert.Equal(t, src, decrypted)
	})

	t.Run("mock block with nil functions", func(t *testing.T) {
		mock := &mockBlock{blockSize: 16}
		src := []byte("test")
		dst := make([]byte, len(src))

		// Should not panic and should copy data
		mock.Encrypt(dst, src)
		assert.Equal(t, src, dst)

		mock.Decrypt(dst, src)
		assert.Equal(t, src, dst)
	})
}
