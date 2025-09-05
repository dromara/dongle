package cipher

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test data for DES cipher
var (
	key8Des = []byte("12345678") // 8-byte key for DES
	iv8Des  = []byte("12345678") // 8-byte IV for DES
)

func TestDesCipher_SetKey(t *testing.T) {
	t.Run("set valid DES keys", func(t *testing.T) {
		validKeys := [][]byte{key8Des}
		for _, key := range validKeys {
			t.Run(fmt.Sprintf("%d-byte key", len(key)), func(t *testing.T) {
				cipher := NewDesCipher(CBC)
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
			{"4-byte key", make([]byte, 4)},
			{"8-byte key", make([]byte, 8)},
			{"16-byte key", make([]byte, 16)},
			{"invalid 7-byte key", make([]byte, 7)},
			{"invalid 9-byte key", make([]byte, 9)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewDesCipher(CBC)
				cipher.SetKey(tc.key)
				assert.Equal(t, tc.key, cipher.Key)
			})
		}
	})
}

func TestDesCipher_SetIV(t *testing.T) {
	t.Run("set different IV values", func(t *testing.T) {
		testCases := []struct {
			name string
			iv   []byte
		}{
			{"valid 8-byte IV", iv8Des},
			{"nil IV", nil},
			{"empty IV", []byte{}},
			{"4-byte IV", make([]byte, 4)},
			{"8-byte IV", make([]byte, 8)},
			{"12-byte IV", make([]byte, 12)},
			{"16-byte IV", make([]byte, 16)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewDesCipher(CBC)
				cipher.SetIV(tc.iv)
				assert.Equal(t, tc.iv, cipher.IV)
			})
		}
	})
}

func TestDesCipher_SetPadding(t *testing.T) {
	t.Run("set all padding modes", func(t *testing.T) {
		paddings := []PaddingMode{
			No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit,
		}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := NewDesCipher(CBC)
				cipher.SetPadding(padding)
				assert.Equal(t, padding, cipher.Padding)
			})
		}
	})
}

func TestDesCipher_SetNonce(t *testing.T) {
	t.Run("set different nonce values", func(t *testing.T) {
		testCases := []struct {
			name  string
			nonce []byte
		}{
			{"valid 12-byte nonce", []byte("123456789012")},
			{"nil nonce", nil},
			{"empty nonce", []byte{}},
			{"8-byte nonce", make([]byte, 8)},
			{"12-byte nonce", make([]byte, 12)},
			{"16-byte nonce", make([]byte, 16)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewDesCipher(GCM)
				cipher.SetNonce(tc.nonce)
				assert.Equal(t, tc.nonce, cipher.Nonce)
			})
		}
	})
}

func TestDesCipher_SetAAD(t *testing.T) {
	t.Run("set different AAD values", func(t *testing.T) {
		testCases := []struct {
			name string
			aad  []byte
		}{
			{"valid AAD", []byte("additional authenticated data")},
			{"nil AAD", nil},
			{"empty AAD", []byte{}},
			{"long AAD", []byte("this is a very long additional authenticated data for testing purposes")},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewDesCipher(GCM)
				cipher.SetAAD(tc.aad)
				assert.Equal(t, tc.aad, cipher.AAD)
			})
		}
	})
}
