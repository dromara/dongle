package cipher

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test data for SM4 cipher
var (
	key16Sm4 = []byte("1234567890123456") // 16-byte key for SM4
	iv16Sm4  = []byte("1234567890123456") // 16-byte IV for SM4
)

func TestNewSm4Cipher(t *testing.T) {
	t.Run("create SM4 cipher with different block modes", func(t *testing.T) {
		blockModes := []BlockMode{ECB, CBC, CTR, CFB, OFB, GCM}
		for _, mode := range blockModes {
			t.Run(string(mode), func(t *testing.T) {
				cipher := NewSm4Cipher(mode)
				assert.NotNil(t, cipher)
				assert.Equal(t, mode, cipher.Block)
				assert.Equal(t, No, cipher.Padding)
			})
		}
	})

	t.Run("verify default initialization", func(t *testing.T) {
		cipher := NewSm4Cipher(CBC)
		assert.NotNil(t, cipher)
		assert.Equal(t, CBC, cipher.Block)
		assert.Equal(t, No, cipher.Padding)
		assert.Nil(t, cipher.Key)
		assert.Nil(t, cipher.IV)
		assert.Nil(t, cipher.Nonce)
		assert.Nil(t, cipher.AAD)
	})
}

func TestSm4Cipher_SetKey(t *testing.T) {
	t.Run("set valid SM4 keys", func(t *testing.T) {
		validKeys := [][]byte{key16Sm4}
		for _, key := range validKeys {
			t.Run(fmt.Sprintf("%d-byte key", len(key)), func(t *testing.T) {
				cipher := NewSm4Cipher(CBC)
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
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewSm4Cipher(CBC)
				cipher.SetKey(tc.key)
				assert.Equal(t, tc.key, cipher.Key)
			})
		}
	})
}

func TestSm4Cipher_SetIV(t *testing.T) {
	t.Run("set different IV values", func(t *testing.T) {
		testCases := []struct {
			name string
			iv   []byte
		}{
			{"valid 16-byte IV", iv16Sm4},
			{"nil IV", nil},
			{"empty IV", []byte{}},
			{"8-byte IV", make([]byte, 8)},
			{"12-byte IV", make([]byte, 12)},
			{"16-byte IV", make([]byte, 16)},
			{"32-byte IV", make([]byte, 32)},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := NewSm4Cipher(CBC)
				cipher.SetIV(tc.iv)
				assert.Equal(t, tc.iv, cipher.IV)
			})
		}
	})
}

func TestSm4Cipher_SetPadding(t *testing.T) {
	t.Run("set all padding modes", func(t *testing.T) {
		paddings := []PaddingMode{
			No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit,
		}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := NewSm4Cipher(CBC)
				cipher.SetPadding(padding)
				assert.Equal(t, padding, cipher.Padding)
			})
		}
	})
}

func TestSm4Cipher_SetNonce(t *testing.T) {
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
				cipher := NewSm4Cipher(GCM)
				cipher.SetNonce(tc.nonce)
				assert.Equal(t, tc.nonce, cipher.Nonce)
			})
		}
	})
}

func TestSm4Cipher_SetAAD(t *testing.T) {
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
				cipher := NewSm4Cipher(GCM)
				cipher.SetAAD(tc.aad)
				assert.Equal(t, tc.aad, cipher.AAD)
			})
		}
	})
}

func TestSm4Cipher_Integration(t *testing.T) {
	t.Run("complete cipher configuration", func(t *testing.T) {
		cipher := NewSm4Cipher(CBC)

		// Set all properties
		cipher.SetKey(key16Sm4)
		cipher.SetIV(iv16Sm4)
		cipher.SetPadding(Zero)
		cipher.SetNonce([]byte("123456789012"))
		cipher.SetAAD([]byte("test aad"))

		// Verify all properties are set correctly
		assert.Equal(t, CBC, cipher.Block)
		assert.Equal(t, key16Sm4, cipher.Key)
		assert.Equal(t, iv16Sm4, cipher.IV)
		assert.Equal(t, Zero, cipher.Padding)
		assert.Equal(t, []byte("123456789012"), cipher.Nonce)
		assert.Equal(t, []byte("test aad"), cipher.AAD)
	})

	t.Run("multiple cipher instances", func(t *testing.T) {
		cipher1 := NewSm4Cipher(ECB)
		cipher2 := NewSm4Cipher(CBC)

		cipher1.SetKey([]byte("key1key1key1key1"))
		cipher2.SetKey([]byte("key2key2key2key2"))

		assert.NotEqual(t, cipher1.Key, cipher2.Key)
		assert.Equal(t, ECB, cipher1.Block)
		assert.Equal(t, CBC, cipher2.Block)
	})
}
