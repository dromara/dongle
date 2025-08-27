package cipher

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test data for RC4 cipher
var (
	key1Rc4   = []byte("1")                                // 1-byte key for RC4
	key4Rc4   = []byte("1234")                             // 4-byte key for RC4
	key8Rc4   = []byte("12345678")                         // 8-byte key for RC4
	key16Rc4  = []byte("1234567890123456")                 // 16-byte key for RC4
	key32Rc4  = []byte("12345678901234567890123456789012") // 32-byte key for RC4
	key256Rc4 = make([]byte, 256)                          // 256-byte key for RC4 (maximum)
)

func TestRc4Cipher_SetKey(t *testing.T) {
	t.Run("set valid RC4 keys", func(t *testing.T) {
		// Initialize 256-byte key with incremental values
		for i := range key256Rc4 {
			key256Rc4[i] = byte(i)
		}

		validKeys := [][]byte{key1Rc4, key4Rc4, key8Rc4, key16Rc4, key32Rc4, key256Rc4}
		for _, key := range validKeys {
			t.Run(fmt.Sprintf("%d-byte key", len(key)), func(t *testing.T) {
				cipher := NewRc4Cipher()
				cipher.SetKey(key)
				assert.Equal(t, key, cipher.Key)
			})
		}
	})

	t.Run("set different key values", func(t *testing.T) {
		testCases := []struct {
			name string
			key  []byte
		}{
			{"nil key", nil},
			{"empty key", []byte{}},
			{"1-byte key", make([]byte, 1)},
			{"4-byte key", make([]byte, 4)},
			{"8-byte key", make([]byte, 8)},
			{"16-byte key", make([]byte, 16)},
			{"32-byte key", make([]byte, 32)},
			{"64-byte key", make([]byte, 64)},
			{"128-byte key", make([]byte, 128)},
			{"256-byte key", make([]byte, 256)},
			{"invalid 257-byte key", make([]byte, 257)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewRc4Cipher()
				cipher.SetKey(tc.key)
				assert.Equal(t, tc.key, cipher.Key)
			})
		}
	})
}
