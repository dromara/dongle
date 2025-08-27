package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test data for 3DES cipher
var (
	key243des = []byte("123456789012345678901234") // 24-byte key for 3DES
	iv83des   = []byte("12345678")                 // 8-byte IV for 3DES (DES block size)
)

func TestTripleDesCipher_SetKey(t *testing.T) {
	t.Run("set valid 24-byte key", func(t *testing.T) {
		cipher := New3DesCipher(CBC)
		cipher.SetKey(key243des)
		assert.Equal(t, key243des, cipher.Key)
	})

	t.Run("set different key values", func(t *testing.T) {
		testCases := []struct {
			name string
			key  []byte
		}{
			{"nil key", nil},
			{"empty key", []byte{}},
			{"8-byte key", make([]byte, 8)},
			{"16-byte key", make([]byte, 16)},
			{"24-byte key", make([]byte, 24)},
			{"32-byte key", make([]byte, 32)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := New3DesCipher(CBC)
				cipher.SetKey(tc.key)
				assert.Equal(t, tc.key, cipher.Key)
			})
		}
	})
}

func TestTripleDesCipher_SetIV(t *testing.T) {
	t.Run("set different IV values", func(t *testing.T) {
		testCases := []struct {
			name string
			iv   []byte
		}{
			{"valid 8-byte IV", iv83des},
			{"nil IV", nil},
			{"empty IV", []byte{}},
			{"4-byte IV", make([]byte, 4)},
			{"12-byte IV", make([]byte, 12)},
			{"16-byte IV", make([]byte, 16)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := New3DesCipher(CBC)
				cipher.SetIV(tc.iv)
				assert.Equal(t, tc.iv, cipher.IV)
			})
		}
	})
}

func TestTripleDesCipher_SetPadding(t *testing.T) {
	t.Run("set all padding modes", func(t *testing.T) {
		paddings := []PaddingMode{
			No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit,
		}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := New3DesCipher(CBC)
				cipher.SetPadding(padding)
				assert.Equal(t, padding, cipher.Padding)
			})
		}
	})
}

func TestTripleDesCipher_SetNonce(t *testing.T) {
	t.Run("set different nonce values", func(t *testing.T) {
		testCases := []struct {
			name  string
			nonce []byte
		}{
			{"valid 12-byte nonce", []byte("123456789012")},
			{"nil nonce", nil},
			{"empty nonce", []byte{}},
			{"8-byte nonce", make([]byte, 8)},
			{"16-byte nonce", make([]byte, 16)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := New3DesCipher(GCM)
				cipher.SetNonce(tc.nonce)
				assert.Equal(t, tc.nonce, cipher.Nonce)
			})
		}
	})
}

func TestTripleDesCipher_SetAAD(t *testing.T) {
	t.Run("set different AAD values", func(t *testing.T) {
		testCases := []struct {
			name string
			aad  []byte
		}{
			{"valid AAD", []byte("additional authenticated data")},
			{"nil AAD", nil},
			{"empty AAD", []byte{}},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := New3DesCipher(GCM)
				cipher.SetAAD(tc.aad)
				assert.Equal(t, tc.aad, cipher.Aad)
			})
		}
	})
}
