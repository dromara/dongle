package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBlowfishCipher(t *testing.T) {
	t.Run("create with CBC mode", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		assert.NotNil(t, cipher)
		assert.Equal(t, CBC, cipher.Block)
		assert.Equal(t, PKCS7, cipher.Padding) // Default padding
		assert.Nil(t, cipher.Key)
		assert.Nil(t, cipher.IV)
		assert.Nil(t, cipher.Nonce)
		assert.Nil(t, cipher.Aad)
	})

	t.Run("create with ECB mode", func(t *testing.T) {
		cipher := NewBlowfishCipher(ECB)
		assert.NotNil(t, cipher)
		assert.Equal(t, ECB, cipher.Block)
		assert.Equal(t, PKCS7, cipher.Padding) // Default padding
		assert.Nil(t, cipher.Key)
		assert.Nil(t, cipher.IV)
		assert.Nil(t, cipher.Nonce)
		assert.Nil(t, cipher.Aad)
	})

	t.Run("create with CTR mode", func(t *testing.T) {
		cipher := NewBlowfishCipher(CTR)
		assert.NotNil(t, cipher)
		assert.Equal(t, CTR, cipher.Block)
		assert.Equal(t, PKCS7, cipher.Padding) // Default padding
		assert.Nil(t, cipher.Key)
		assert.Nil(t, cipher.IV)
		assert.Nil(t, cipher.Nonce)
		assert.Nil(t, cipher.Aad)
	})

	t.Run("create with GCM mode", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		assert.NotNil(t, cipher)
		assert.Equal(t, GCM, cipher.Block)
		assert.Equal(t, PKCS7, cipher.Padding) // Default padding
		assert.Nil(t, cipher.Key)
		assert.Nil(t, cipher.IV)
		assert.Nil(t, cipher.Nonce)
		assert.Nil(t, cipher.Aad)
	})

	t.Run("create with CFB mode", func(t *testing.T) {
		cipher := NewBlowfishCipher(CFB)
		assert.NotNil(t, cipher)
		assert.Equal(t, CFB, cipher.Block)
		assert.Equal(t, PKCS7, cipher.Padding) // Default padding
		assert.Nil(t, cipher.Key)
		assert.Nil(t, cipher.IV)
		assert.Nil(t, cipher.Nonce)
		assert.Nil(t, cipher.Aad)
	})

	t.Run("create with OFB mode", func(t *testing.T) {
		cipher := NewBlowfishCipher(OFB)
		assert.NotNil(t, cipher)
		assert.Equal(t, OFB, cipher.Block)
		assert.Equal(t, PKCS7, cipher.Padding) // Default padding
		assert.Nil(t, cipher.Key)
		assert.Nil(t, cipher.IV)
		assert.Nil(t, cipher.Nonce)
		assert.Nil(t, cipher.Aad)
	})
}

func TestBlowfishCipher_SetPadding(t *testing.T) {
	t.Run("set No padding", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetPadding(No)
		assert.Equal(t, No, cipher.Padding)
	})

	t.Run("set Zero padding", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetPadding(Zero)
		assert.Equal(t, Zero, cipher.Padding)
	})

	t.Run("set PKCS5 padding", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetPadding(PKCS5)
		assert.Equal(t, PKCS5, cipher.Padding)
	})

	t.Run("set PKCS7 padding", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetPadding(PKCS7)
		assert.Equal(t, PKCS7, cipher.Padding)
	})

	t.Run("set AnsiX923 padding", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetPadding(AnsiX923)
		assert.Equal(t, AnsiX923, cipher.Padding)
	})

	t.Run("set ISO97971 padding", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetPadding(ISO97971)
		assert.Equal(t, ISO97971, cipher.Padding)
	})

	t.Run("set ISO10126 padding", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetPadding(ISO10126)
		assert.Equal(t, ISO10126, cipher.Padding)
	})

	t.Run("set ISO78164 padding", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetPadding(ISO78164)
		assert.Equal(t, ISO78164, cipher.Padding)
	})

	t.Run("set Bit padding", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetPadding(Bit)
		assert.Equal(t, Bit, cipher.Padding)
	})

	t.Run("change padding multiple times", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		assert.Equal(t, PKCS7, cipher.Padding) // Default

		cipher.SetPadding(No)
		assert.Equal(t, No, cipher.Padding)

		cipher.SetPadding(Zero)
		assert.Equal(t, Zero, cipher.Padding)

		cipher.SetPadding(PKCS7)
		assert.Equal(t, PKCS7, cipher.Padding)
	})
}

func TestBlowfishCipher_SetKey(t *testing.T) {
	t.Run("set 8-byte key (Blowfish)", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		key := make([]byte, 8)
		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Equal(t, 8, len(cipher.Key))
	})

	t.Run("set 16-byte key (Blowfish)", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		key := make([]byte, 16)
		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Equal(t, 16, len(cipher.Key))
	})

	t.Run("set 32-byte key (Blowfish)", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		key := make([]byte, 32)
		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Equal(t, 32, len(cipher.Key))
	})

	t.Run("set 56-byte key (Blowfish)", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		key := make([]byte, 56)
		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Equal(t, 56, len(cipher.Key))
	})

	t.Run("set empty key", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		key := []byte{}
		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)
		assert.Equal(t, 0, len(cipher.Key))
	})

	t.Run("set nil key", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetKey(nil)
		assert.Nil(t, cipher.Key)
	})

	t.Run("change key multiple times", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		assert.Nil(t, cipher.Key)

		key1 := make([]byte, 8)
		cipher.SetKey(key1)
		assert.Equal(t, key1, cipher.Key)

		key2 := make([]byte, 16)
		cipher.SetKey(key2)
		assert.Equal(t, key2, cipher.Key)
		assert.NotEqual(t, key1, cipher.Key)
	})
}

func TestBlowfishCipher_SetIV(t *testing.T) {
	t.Run("set 8-byte IV", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		iv := make([]byte, 8)
		cipher.SetIV(iv)
		assert.Equal(t, iv, cipher.IV)
		assert.Equal(t, 8, len(cipher.IV))
	})

	t.Run("set 12-byte nonce for GCM", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		nonce := make([]byte, 12)
		cipher.SetIV(nonce)
		assert.Equal(t, nonce, cipher.IV)
		assert.Equal(t, 12, len(cipher.IV))
	})

	t.Run("set empty IV", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		iv := []byte{}
		cipher.SetIV(iv)
		assert.Equal(t, iv, cipher.IV)
		assert.Equal(t, 0, len(cipher.IV))
	})

	t.Run("set nil IV", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetIV(nil)
		assert.Nil(t, cipher.IV)
	})

	t.Run("change IV multiple times", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		assert.Nil(t, cipher.IV)

		iv1 := make([]byte, 8)
		cipher.SetIV(iv1)
		assert.Equal(t, iv1, cipher.IV)

		iv2 := make([]byte, 12)
		cipher.SetIV(iv2)
		assert.Equal(t, iv2, cipher.IV)
		assert.NotEqual(t, iv1, cipher.IV)
	})
}

func TestBlowfishCipher_SetNonce(t *testing.T) {
	t.Run("set 12-byte nonce", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		nonce := make([]byte, 12)
		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Equal(t, 12, len(cipher.Nonce))
	})

	t.Run("set 8-byte nonce", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		nonce := make([]byte, 8)
		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Equal(t, 8, len(cipher.Nonce))
	})

	t.Run("set empty nonce", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		nonce := []byte{}
		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Equal(t, 0, len(cipher.Nonce))
	})

	t.Run("set nil nonce", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		cipher.SetNonce(nil)
		assert.Nil(t, cipher.Nonce)
	})

	t.Run("change nonce multiple times", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		assert.Nil(t, cipher.Nonce)

		nonce1 := make([]byte, 12)
		cipher.SetNonce(nonce1)
		assert.Equal(t, nonce1, cipher.Nonce)

		nonce2 := make([]byte, 8)
		cipher.SetNonce(nonce2)
		assert.Equal(t, nonce2, cipher.Nonce)
		assert.NotEqual(t, nonce1, cipher.Nonce)
	})

	t.Run("set nonce for non-GCM mode", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		nonce := make([]byte, 12)
		cipher.SetNonce(nonce)
		assert.Equal(t, nonce, cipher.Nonce)
		// Nonce can be set for any mode, but only used by GCM
	})
}

func TestBlowfishCipher_SetAAD(t *testing.T) {
	t.Run("set AAD data", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		aad := []byte("additional authenticated data")
		cipher.SetAAD(aad)
		assert.Equal(t, aad, cipher.Aad)
		assert.Equal(t, len("additional authenticated data"), len(cipher.Aad))
	})

	t.Run("set empty AAD", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		aad := []byte{}
		cipher.SetAAD(aad)
		assert.Equal(t, aad, cipher.Aad)
		assert.Equal(t, 0, len(cipher.Aad))
	})

	t.Run("set nil AAD", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		cipher.SetAAD(nil)
		assert.Nil(t, cipher.Aad)
	})

	t.Run("change AAD multiple times", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		assert.Nil(t, cipher.Aad)

		aad1 := []byte("first AAD")
		cipher.SetAAD(aad1)
		assert.Equal(t, aad1, cipher.Aad)

		aad2 := []byte("second AAD")
		cipher.SetAAD(aad2)
		assert.Equal(t, aad2, cipher.Aad)
		assert.NotEqual(t, aad1, cipher.Aad)
	})

	t.Run("set AAD for non-GCM mode", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		aad := []byte("AAD for CBC mode")
		cipher.SetAAD(aad)
		assert.Equal(t, aad, cipher.Aad)
		// AAD can be set for any mode, but only used by GCM
	})
}

func TestBlowfishCipher_Integration(t *testing.T) {
	t.Run("complete cipher configuration", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)

		// Set all properties
		key := make([]byte, 16)
		iv := make([]byte, 8)
		nonce := make([]byte, 12)
		aad := []byte("test AAD")

		cipher.SetKey(key)
		cipher.SetIV(iv)
		cipher.SetNonce(nonce)
		cipher.SetAAD(aad)
		cipher.SetPadding(Zero)

		// Verify all properties
		assert.Equal(t, CBC, cipher.Block)
		assert.Equal(t, Zero, cipher.Padding)
		assert.Equal(t, key, cipher.Key)
		assert.Equal(t, iv, cipher.IV)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Equal(t, aad, cipher.Aad)
	})

	t.Run("reconfigure existing cipher", func(t *testing.T) {
		cipher := NewBlowfishCipher(ECB)

		// Initial configuration
		key1 := make([]byte, 8)
		cipher.SetKey(key1)
		cipher.SetPadding(PKCS5)

		// Reconfigure
		key2 := make([]byte, 16)
		cipher.SetKey(key2)
		cipher.SetPadding(No)

		// Verify changes
		assert.Equal(t, ECB, cipher.Block)
		assert.Equal(t, No, cipher.Padding)
		assert.Equal(t, key2, cipher.Key)
		assert.NotEqual(t, key1, cipher.Key)
	})

	t.Run("multiple mode configurations", func(t *testing.T) {
		// Test CBC mode
		cbcCipher := NewBlowfishCipher(CBC)
		cbcCipher.SetKey(make([]byte, 16))
		cbcCipher.SetIV(make([]byte, 8))
		cbcCipher.SetPadding(PKCS7)

		assert.Equal(t, CBC, cbcCipher.Block)
		assert.Equal(t, 16, len(cbcCipher.Key))
		assert.Equal(t, 8, len(cbcCipher.IV))
		assert.Equal(t, PKCS7, cbcCipher.Padding)

		// Test GCM mode
		gcmCipher := NewBlowfishCipher(GCM)
		gcmCipher.SetKey(make([]byte, 32))
		gcmCipher.SetNonce(make([]byte, 12))
		gcmCipher.SetAAD([]byte("GCM AAD"))
		gcmCipher.SetPadding(No)

		assert.Equal(t, GCM, gcmCipher.Block)
		assert.Equal(t, 32, len(gcmCipher.Key))
		assert.Equal(t, 12, len(gcmCipher.Nonce))
		assert.Equal(t, []byte("GCM AAD"), gcmCipher.Aad)
		assert.Equal(t, No, gcmCipher.Padding)
	})
}

func TestBlowfishCipher_EdgeCases(t *testing.T) {
	t.Run("zero-length key", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetKey([]byte{})
		assert.Equal(t, 0, len(cipher.Key))
	})

	t.Run("zero-length IV", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		cipher.SetIV([]byte{})
		assert.Equal(t, 0, len(cipher.IV))
	})

	t.Run("zero-length nonce", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		cipher.SetNonce([]byte{})
		assert.Equal(t, 0, len(cipher.Nonce))
	})

	t.Run("zero-length AAD", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		cipher.SetAAD([]byte{})
		assert.Equal(t, 0, len(cipher.Aad))
	})

	t.Run("very long key", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		longKey := make([]byte, 1024)
		cipher.SetKey(longKey)
		assert.Equal(t, 1024, len(cipher.Key))
	})

	t.Run("very long IV", func(t *testing.T) {
		cipher := NewBlowfishCipher(CBC)
		longIV := make([]byte, 1024)
		cipher.SetIV(longIV)
		assert.Equal(t, 1024, len(cipher.IV))
	})

	t.Run("very long nonce", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		longNonce := make([]byte, 1024)
		cipher.SetNonce(longNonce)
		assert.Equal(t, 1024, len(cipher.Nonce))
	})

	t.Run("very long AAD", func(t *testing.T) {
		cipher := NewBlowfishCipher(GCM)
		longAAD := make([]byte, 1024)
		cipher.SetAAD(longAAD)
		assert.Equal(t, 1024, len(cipher.Aad))
	})
}

func TestBlowfishCipher_FieldAccess(t *testing.T) {
	t.Run("direct field access", func(t *testing.T) {
		cipher := NewBlowfishCipher(CTR)

		// Set values
		key := make([]byte, 16)
		iv := make([]byte, 8)
		nonce := make([]byte, 12)
		aad := []byte("test")

		cipher.Key = key
		cipher.IV = iv
		cipher.Nonce = nonce
		cipher.Aad = aad
		cipher.Padding = Zero

		// Verify direct access
		assert.Equal(t, key, cipher.Key)
		assert.Equal(t, iv, cipher.IV)
		assert.Equal(t, nonce, cipher.Nonce)
		assert.Equal(t, aad, cipher.Aad)
		assert.Equal(t, Zero, cipher.Padding)
	})

	t.Run("field modification after setter", func(t *testing.T) {
		cipher := NewBlowfishCipher(CFB)

		// Use setter
		key := make([]byte, 16)
		cipher.SetKey(key)
		assert.Equal(t, key, cipher.Key)

		// Modify field directly
		modifiedKey := make([]byte, 32)
		cipher.Key = modifiedKey
		assert.Equal(t, modifiedKey, cipher.Key)
		assert.Equal(t, 32, len(cipher.Key))
	})
}
