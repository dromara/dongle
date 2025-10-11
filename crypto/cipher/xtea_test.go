package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test data for XTEA cipher
var (
	key16Xtea = []byte("1234567890123456") // 16-byte key for XTEA
	iv8Xtea   = []byte("12345678")         // 8-byte IV for XTEA
)

func TestNewXteaCipher(t *testing.T) {
	t.Run("create XTEA cipher with different block modes", func(t *testing.T) {
		blockModes := []BlockMode{CBC, ECB, CTR, GCM, CFB, OFB}
		for _, mode := range blockModes {
			t.Run(string(mode), func(t *testing.T) {
				cipher := NewXteaCipher(mode)
				assert.NotNil(t, cipher)
				assert.Equal(t, mode, cipher.Block)
				assert.Equal(t, PKCS7, cipher.Padding) // Default padding should be PKCS7
			})
		}
	})

	t.Run("create XTEA cipher with nil block mode", func(t *testing.T) {
		cipher := NewXteaCipher(BlockMode(""))
		assert.NotNil(t, cipher)
		assert.Equal(t, BlockMode(""), cipher.Block)
		assert.Equal(t, PKCS7, cipher.Padding)
	})
}

func TestXteaCipher_SetKey(t *testing.T) {
	t.Run("set valid XTEA key", func(t *testing.T) {
		cipher := NewXteaCipher(CBC)
		key := key16Xtea

		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
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
			{"32-byte key", make([]byte, 32)},
			{"invalid 15-byte key", make([]byte, 15)},
			{"invalid 17-byte key", make([]byte, 17)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewXteaCipher(CBC)
				cipher.SetKey(tc.key)
				assert.Equal(t, tc.key, cipher.Key)
			})
		}
	})

	t.Run("overwrite existing key", func(t *testing.T) {
		cipher := NewXteaCipher(CBC)
		key1 := []byte("firstkey12345678")
		key2 := []byte("secondkey1234567")

		cipher.SetKey(key1)
		assert.Equal(t, key1, cipher.Key)

		cipher.SetKey(key2)
		assert.Equal(t, key2, cipher.Key)
		assert.NotEqual(t, key1, cipher.Key)
	})
}

func TestXteaCipher_SetIV(t *testing.T) {
	t.Run("set different IV values", func(t *testing.T) {
		testCases := []struct {
			name string
			iv   []byte
		}{
			{"valid 8-byte IV", iv8Xtea},
			{"nil IV", nil},
			{"empty IV", []byte{}},
			{"4-byte IV", make([]byte, 4)},
			{"8-byte IV", make([]byte, 8)},
			{"12-byte IV", make([]byte, 12)},
			{"16-byte IV", make([]byte, 16)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewXteaCipher(CBC)
				cipher.SetIV(tc.iv)
				assert.Equal(t, tc.iv, cipher.IV)
			})
		}
	})

	t.Run("overwrite existing IV", func(t *testing.T) {
		cipher := NewXteaCipher(CBC)
		iv1 := []byte("12345678")
		iv2 := []byte("87654321")

		cipher.SetIV(iv1)
		assert.Equal(t, iv1, cipher.IV)

		cipher.SetIV(iv2)
		assert.Equal(t, iv2, cipher.IV)
		assert.NotEqual(t, iv1, cipher.IV)
	})
}

func TestXteaCipher_SetPadding(t *testing.T) {
	t.Run("set all padding modes", func(t *testing.T) {
		paddings := []PaddingMode{
			No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit,
		}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := NewXteaCipher(CBC)
				cipher.SetPadding(padding)
				assert.Equal(t, padding, cipher.Padding)
			})
		}
	})

	t.Run("overwrite existing padding", func(t *testing.T) {
		cipher := NewXteaCipher(CBC)
		assert.Equal(t, PKCS7, cipher.Padding) // Default padding

		cipher.SetPadding(Zero)
		assert.Equal(t, Zero, cipher.Padding)

		cipher.SetPadding(PKCS5)
		assert.Equal(t, PKCS5, cipher.Padding)
		assert.NotEqual(t, Zero, cipher.Padding)
	})
}

func TestXteaCipher_SetNonce(t *testing.T) {
	t.Run("set different nonce values", func(t *testing.T) {
		testCases := []struct {
			name  string
			nonce []byte
		}{
			{"valid 8-byte nonce", []byte("12345678")},
			{"nil nonce", nil},
			{"empty nonce", []byte{}},
			{"4-byte nonce", make([]byte, 4)},
			{"8-byte nonce", make([]byte, 8)},
			{"12-byte nonce", make([]byte, 12)},
			{"16-byte nonce", make([]byte, 16)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewXteaCipher(GCM)
				cipher.SetNonce(tc.nonce)
				assert.Equal(t, tc.nonce, cipher.Nonce)
			})
		}
	})

	t.Run("overwrite existing nonce", func(t *testing.T) {
		cipher := NewXteaCipher(GCM)
		nonce1 := []byte("12345678")
		nonce2 := []byte("87654321")

		cipher.SetNonce(nonce1)
		assert.Equal(t, nonce1, cipher.Nonce)

		cipher.SetNonce(nonce2)
		assert.Equal(t, nonce2, cipher.Nonce)
		assert.NotEqual(t, nonce1, cipher.Nonce)
	})
}

func TestXteaCipher_SetAAD(t *testing.T) {
	t.Run("set different AAD values", func(t *testing.T) {
		testCases := []struct {
			name string
			aad  []byte
		}{
			{"valid AAD", []byte("additional authenticated data")},
			{"nil AAD", nil},
			{"empty AAD", []byte{}},
			{"short AAD", []byte("short")},
			{"long AAD", []byte("this is a very long additional authenticated data for testing purposes")},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewXteaCipher(GCM)
				cipher.SetAAD(tc.aad)
				assert.Equal(t, tc.aad, cipher.AAD)
			})
		}
	})

	t.Run("overwrite existing AAD", func(t *testing.T) {
		cipher := NewXteaCipher(GCM)
		aad1 := []byte("first aad")
		aad2 := []byte("second aad")

		cipher.SetAAD(aad1)
		assert.Equal(t, aad1, cipher.AAD)

		cipher.SetAAD(aad2)
		assert.Equal(t, aad2, cipher.AAD)
		assert.NotEqual(t, aad1, cipher.AAD)
	})
}

func TestXteaCipher_Encrypt(t *testing.T) {
	t.Run("encrypt with stream modes (no padding)", func(t *testing.T) {
		// Test stream modes that don't require padding
		streamModes := []BlockMode{CFB, OFB, CTR, GCM}
		for _, mode := range streamModes {
			t.Run(string(mode), func(t *testing.T) {
				cipher := NewXteaCipher(mode)
				cipher.SetKey(key16Xtea)
				if mode == GCM {
					cipher.SetNonce([]byte("12345678"))
					cipher.SetAAD([]byte("aad"))
				} else {
					cipher.SetIV(iv8Xtea)
				}

				// Test with empty data - should return error due to nil block
				dst, err := cipher.Encrypt([]byte{}, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cipher block cannot be nil")
				assert.Empty(t, dst)
			})
		}
	})
}

func TestXteaCipher_Decrypt(t *testing.T) {
	t.Run("decrypt with stream modes (no padding)", func(t *testing.T) {
		// Test stream modes that don't require padding
		streamModes := []BlockMode{CFB, OFB, CTR, GCM}
		for _, mode := range streamModes {
			t.Run(string(mode), func(t *testing.T) {
				cipher := NewXteaCipher(mode)
				cipher.SetKey(key16Xtea)
				if mode == GCM {
					cipher.SetNonce([]byte("12345678"))
					cipher.SetAAD([]byte("aad"))
				} else {
					cipher.SetIV(iv8Xtea)
				}

				// Test with empty data - should return error due to nil block
				dst, err := cipher.Decrypt([]byte{}, nil)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "cipher block cannot be nil")
				assert.Empty(t, dst)
			})
		}
	})
}

func TestXteaCipher_Integration(t *testing.T) {
	t.Run("complete cipher configuration", func(t *testing.T) {
		cipher := NewXteaCipher(CBC)
		cipher.SetKey(key16Xtea)
		cipher.SetIV(iv8Xtea)
		cipher.SetPadding(Zero)
		cipher.SetNonce([]byte("12345678"))
		cipher.SetAAD([]byte("test aad"))

		// Verify all settings
		assert.Equal(t, CBC, cipher.Block)
		assert.Equal(t, key16Xtea, cipher.Key)
		assert.Equal(t, iv8Xtea, cipher.IV)
		assert.Equal(t, Zero, cipher.Padding)
		assert.Equal(t, []byte("12345678"), cipher.Nonce)
		assert.Equal(t, []byte("test aad"), cipher.AAD)
	})

	t.Run("cipher with different configurations", func(t *testing.T) {
		testCases := []struct {
			name    string
			mode    BlockMode
			key     []byte
			iv      []byte
			padding PaddingMode
			nonce   []byte
			aad     []byte
		}{
			{
				name:    "ECB mode",
				mode:    ECB,
				key:     key16Xtea,
				padding: PKCS7,
			},
			{
				name:    "CBC mode",
				mode:    CBC,
				key:     key16Xtea,
				iv:      iv8Xtea,
				padding: Zero,
			},
			{
				name:    "CTR mode",
				mode:    CTR,
				key:     key16Xtea,
				iv:      iv8Xtea,
				padding: No,
			},
			{
				name:    "GCM mode",
				mode:    GCM,
				key:     key16Xtea,
				nonce:   []byte("12345678"),
				aad:     []byte("aad"),
				padding: No,
			},
			{
				name:    "CFB mode",
				mode:    CFB,
				key:     key16Xtea,
				iv:      iv8Xtea,
				padding: PKCS5,
			},
			{
				name:    "OFB mode",
				mode:    OFB,
				key:     key16Xtea,
				iv:      iv8Xtea,
				padding: AnsiX923,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewXteaCipher(tc.mode)
				cipher.SetKey(tc.key)
				if tc.iv != nil {
					cipher.SetIV(tc.iv)
				}
				cipher.SetPadding(tc.padding)
				if tc.nonce != nil {
					cipher.SetNonce(tc.nonce)
				}
				if tc.aad != nil {
					cipher.SetAAD(tc.aad)
				}

				// Verify configuration
				assert.Equal(t, tc.mode, cipher.Block)
				assert.Equal(t, tc.key, cipher.Key)
				if tc.iv != nil {
					assert.Equal(t, tc.iv, cipher.IV)
				}
				assert.Equal(t, tc.padding, cipher.Padding)
				if tc.nonce != nil {
					assert.Equal(t, tc.nonce, cipher.Nonce)
				}
				if tc.aad != nil {
					assert.Equal(t, tc.aad, cipher.AAD)
				}
			})
		}
	})
}
