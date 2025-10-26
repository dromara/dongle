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
		assert.IsType(t, InvalidPlaintextError{}, err)
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
		assert.IsType(t, InvalidCiphertextError{}, err)
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

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewCTREncrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})

	t.Run("invalid IV length - too short", func(t *testing.T) {
		invalidIV := make([]byte, 8) // Too short
		result, err := NewCTREncrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 8 must equal block size 16")
	})

	t.Run("invalid IV length - too long", func(t *testing.T) {
		invalidIV := make([]byte, 20) // Too long
		result, err := NewCTREncrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 20 must equal block size 16")
	})

	t.Run("invalid IV length - 15 bytes", func(t *testing.T) {
		invalidIV := make([]byte, 15) // Neither 12 nor 16
		result, err := NewCTREncrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 15 must equal block size 16")
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

	t.Run("empty IV", func(t *testing.T) {
		result, err := NewCTRDecrypter(src, []byte{}, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EmptyIVError{}, err)
		assert.Contains(t, err.Error(), "iv cannot be empty")
	})

	t.Run("invalid IV length - too short", func(t *testing.T) {
		invalidIV := make([]byte, 8) // Too short
		result, err := NewCTRDecrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 8 must equal block size 16")
	})

	t.Run("invalid IV length - too long", func(t *testing.T) {
		invalidIV := make([]byte, 20) // Too long
		result, err := NewCTRDecrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 20 must equal block size 16")
	})

	t.Run("invalid IV length - 15 bytes", func(t *testing.T) {
		invalidIV := make([]byte, 15) // Neither 12 nor 16
		result, err := NewCTRDecrypter(src, invalidIV, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidIVError{}, err)
		assert.Contains(t, err.Error(), "iv length 15 must equal block size 16")
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
		assert.IsType(t, InvalidPlaintextError{}, err)
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
		assert.IsType(t, InvalidCiphertextError{}, err)
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

	t.Run("successful encryption with 8-byte nonce", func(t *testing.T) {
		nonce8 := make([]byte, 8)
		result, err := NewGCMEncrypter(src, nonce8, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.NotEqual(t, src, result)        // Should be encrypted
		assert.True(t, len(result) > len(src)) // GCM adds authentication tag
	})

	t.Run("successful encryption with 16-byte nonce", func(t *testing.T) {
		nonce16 := make([]byte, 16)
		result, err := NewGCMEncrypter(src, nonce16, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.NotEqual(t, src, result)        // Should be encrypted
		assert.True(t, len(result) > len(src)) // GCM adds authentication tag
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
	})

	t.Run("successful decryption with 8-byte nonce", func(t *testing.T) {
		nonce8 := make([]byte, 8)
		// First encrypt some data with 8-byte nonce
		encrypted, err := NewGCMEncrypter([]byte("test data"), nonce8, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)

		// Then decrypt it with 8-byte nonce
		result, err := NewGCMDecrypter(encrypted, nonce8, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, []byte("test data"), result)
	})

	t.Run("successful decryption with 16-byte nonce", func(t *testing.T) {
		nonce16 := make([]byte, 16)
		// First encrypt some data with 16-byte nonce
		encrypted, err := NewGCMEncrypter([]byte("test data"), nonce16, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)

		// Then decrypt it with 16-byte nonce
		result, err := NewGCMDecrypter(encrypted, nonce16, aad, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, []byte("test data"), result)
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
		err := InvalidCiphertextError{
			mode: CBC,
			src:  []byte("test"),
			size: 16,
		}
		msg := err.Error()
		assert.Contains(t, msg, "CBC")
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

func TestInvalidPlaintextErrorScenarios(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)

	t.Run("CBC with No padding and invalid data length", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: No,
			IV:      iv,
		}

		// Use data that is not a multiple of block size
		invalidData := make([]byte, 17) // 17 bytes, not multiple of 16
		result, err := cipher.Encrypt(invalidData, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPlaintextError{}, err)
		assert.Contains(t, err.Error(), "plaintext length 17 must be a multiple of block size 16")
		assert.Contains(t, err.Error(), "CBC")
	})

	t.Run("ECB with No padding and invalid data length", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   ECB,
			Padding: No,
			IV:      iv,
		}

		// Use data that is not a multiple of block size
		invalidData := make([]byte, 15) // 15 bytes, not multiple of 16
		result, err := cipher.Encrypt(invalidData, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPlaintextError{}, err)
		assert.Contains(t, err.Error(), "plaintext length 15 must be a multiple of block size 16")
		assert.Contains(t, err.Error(), "ECB")
	})

	t.Run("CBC with No padding and single byte data", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: No,
			IV:      iv,
		}

		// Use single byte data
		invalidData := []byte("a") // 1 byte, not multiple of 16
		result, err := cipher.Encrypt(invalidData, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPlaintextError{}, err)
		assert.Contains(t, err.Error(), "plaintext length 1 must be a multiple of block size 16")
		assert.Contains(t, err.Error(), "CBC")
	})

	t.Run("ECB with No padding and single byte data", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   ECB,
			Padding: No,
			IV:      iv,
		}

		// Use single byte data
		invalidData := []byte("b") // 1 byte, not multiple of 16
		result, err := cipher.Encrypt(invalidData, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, InvalidPlaintextError{}, err)
		assert.Contains(t, err.Error(), "plaintext length 1 must be a multiple of block size 16")
		assert.Contains(t, err.Error(), "ECB")
	})

	t.Run("CBC with No padding and empty data", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: No,
			IV:      iv,
		}

		// Use empty data - 0 is considered a multiple of any number
		emptyData := []byte{} // 0 bytes, 0 is multiple of 16
		result, err := cipher.Encrypt(emptyData, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 0, len(result))
	})

	t.Run("ECB with No padding and empty data", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   ECB,
			Padding: No,
			IV:      iv,
		}

		// Use empty data - 0 is considered a multiple of any number
		emptyData := []byte{} // 0 bytes, 0 is multiple of 16
		result, err := cipher.Encrypt(emptyData, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 0, len(result))
	})

	t.Run("CBC with No padding and data length equals block size", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: No,
			IV:      iv,
		}

		// Use data that is exactly block size
		validData := make([]byte, 16) // 16 bytes, exactly block size
		result, err := cipher.Encrypt(validData, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(validData), len(result))
	})

	t.Run("ECB with No padding and data length equals block size", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   ECB,
			Padding: No,
			IV:      iv,
		}

		// Use data that is exactly block size
		validData := make([]byte, 16) // 16 bytes, exactly block size
		result, err := cipher.Encrypt(validData, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(validData), len(result))
	})

	t.Run("CBC with No padding and data length equals multiple of block size", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: No,
			IV:      iv,
		}

		// Use data that is multiple of block size
		validData := make([]byte, 32) // 32 bytes, 2 * block size
		result, err := cipher.Encrypt(validData, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(validData), len(result))
	})

	t.Run("ECB with No padding and data length equals multiple of block size", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   ECB,
			Padding: No,
			IV:      iv,
		}

		// Use data that is multiple of block size
		validData := make([]byte, 32) // 32 bytes, 2 * block size
		result, err := cipher.Encrypt(validData, block)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(validData), len(result))
	})
}

func TestUnsupportedBlockMode(t *testing.T) {
	key := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	src := make([]byte, 16)

	t.Run("encrypt with unsupported block mode", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   BlockMode("UNSUPPORTED"),
			Padding: PKCS7,
			IV:      make([]byte, 16),
		}

		result, err := cipher.Encrypt(src, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, UnsupportedBlockModeError{}, err)
		assert.Contains(t, err.Error(), "unsupported block mode")
		assert.Contains(t, err.Error(), "UNSUPPORTED")
	})

	t.Run("decrypt with unsupported block mode", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   BlockMode("UNSUPPORTED"),
			Padding: PKCS7,
			IV:      make([]byte, 16),
		}

		result, err := cipher.Decrypt(src, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, UnsupportedBlockModeError{}, err)
		assert.Contains(t, err.Error(), "unsupported block mode")
		assert.Contains(t, err.Error(), "UNSUPPORTED")
	})
}
