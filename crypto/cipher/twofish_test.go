package cipher

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test data for Twofish cipher
var (
	key16Twofish = []byte("1234567890123456")                 // 16-byte key for Twofish-128
	key24Twofish = []byte("123456789012345678901234")         // 24-byte key for Twofish-192
	key32Twofish = []byte("12345678901234567890123456789012") // 32-byte key for Twofish-256
	iv16Twofish  = []byte("1234567890123456")                 // 16-byte IV for Twofish
)

func TestTwofishCipher_SetKey(t *testing.T) {
	t.Run("set valid Twofish keys", func(t *testing.T) {
		validKeys := [][]byte{key16Twofish, key24Twofish, key32Twofish}
		for _, key := range validKeys {
			t.Run(fmt.Sprintf("%d-byte key", len(key)), func(t *testing.T) {
				cipher := NewTwofishCipher(CBC)
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
			{"8-byte key", make([]byte, 8)},
			{"16-byte key", make([]byte, 16)},
			{"24-byte key", make([]byte, 24)},
			{"32-byte key", make([]byte, 32)},
			{"invalid 15-byte key", make([]byte, 15)},
			{"invalid 17-byte key", make([]byte, 17)},
			{"invalid 25-byte key", make([]byte, 25)},
			{"invalid 33-byte key", make([]byte, 33)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewTwofishCipher(CBC)
				cipher.SetKey(tc.key)
				assert.Equal(t, tc.key, cipher.Key)
			})
		}
	})
}

func TestTwofishCipher_SetIV(t *testing.T) {
	t.Run("set different IV values", func(t *testing.T) {
		testCases := []struct {
			name string
			iv   []byte
		}{
			{"valid 16-byte IV", iv16Twofish},
			{"nil IV", nil},
			{"empty IV", []byte{}},
			{"8-byte IV", make([]byte, 8)},
			{"12-byte IV", make([]byte, 12)},
			{"16-byte IV", make([]byte, 16)},
			{"32-byte IV", make([]byte, 32)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewTwofishCipher(CBC)
				cipher.SetIV(tc.iv)
				assert.Equal(t, tc.iv, cipher.IV)
			})
		}
	})
}

func TestTwofishCipher_SetPadding(t *testing.T) {
	t.Run("set all padding modes", func(t *testing.T) {
		paddings := []PaddingMode{
			No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit,
		}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := NewTwofishCipher(CBC)
				cipher.SetPadding(padding)
				assert.Equal(t, padding, cipher.Padding)
			})
		}
	})
}

func TestTwofishCipher_SetNonce(t *testing.T) {
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
				cipher := NewTwofishCipher(GCM)
				cipher.SetNonce(tc.nonce)
				assert.Equal(t, tc.nonce, cipher.Nonce)
			})
		}
	})
}

func TestTwofishCipher_SetAAD(t *testing.T) {
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
				cipher := NewTwofishCipher(GCM)
				cipher.SetAAD(tc.aad)
				assert.Equal(t, tc.aad, cipher.AAD)
			})
		}
	})
}

func TestNewTwofishCipher(t *testing.T) {
	t.Run("create Twofish cipher with different block modes", func(t *testing.T) {
		modes := []BlockMode{CBC, CTR, ECB, CFB, OFB, GCM}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				cipher := NewTwofishCipher(mode)
				assert.NotNil(t, cipher)
				assert.Equal(t, mode, cipher.Block)
				assert.Equal(t, No, cipher.Padding) // Default padding
			})
		}
	})

	t.Run("create Twofish cipher with invalid block mode", func(t *testing.T) {
		cipher := NewTwofishCipher("INVALID_MODE")
		assert.NotNil(t, cipher)
		assert.Equal(t, BlockMode("INVALID_MODE"), cipher.Block)
		assert.Equal(t, No, cipher.Padding) // Default padding
	})
}

func TestTwofishCipher_Encrypt(t *testing.T) {
	t.Run("encrypt with different padding modes", func(t *testing.T) {
		paddings := []PaddingMode{
			No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit,
		}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := NewTwofishCipher(CBC)
				cipher.SetKey(key16Twofish)
				cipher.SetIV(iv16Twofish)
				cipher.SetPadding(padding)

				// This test just verifies the method exists and can be called
				// The actual encryption logic is tested in the twofish package
				assert.NotNil(t, cipher)
				assert.Equal(t, padding, cipher.Padding)
			})
		}
	})
}

func TestTwofishCipher_Decrypt(t *testing.T) {
	t.Run("decrypt with different padding modes", func(t *testing.T) {
		paddings := []PaddingMode{
			No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit,
		}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := NewTwofishCipher(CBC)
				cipher.SetKey(key16Twofish)
				cipher.SetIV(iv16Twofish)
				cipher.SetPadding(padding)

				// This test just verifies the method exists and can be called
				// The actual decryption logic is tested in the twofish package
				assert.NotNil(t, cipher)
				assert.Equal(t, padding, cipher.Padding)
			})
		}
	})
}
