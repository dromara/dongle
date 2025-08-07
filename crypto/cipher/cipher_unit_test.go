package cipher

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCBCCipher_All(t *testing.T) {
	cbc := NewCBCCipher()
	assert.Equal(t, PKCS7, cbc.padding)
	cbc.SetPadding(Zero)
	assert.Equal(t, Zero, cbc.padding)
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	cbc.SetKey(key)
	cbc.SetIV(iv)
	assert.Equal(t, key, cbc.GetKey())

	block, _ := aes.NewCipher(key)
	// Normal encryption
	plaintext := []byte("hello world!!!")
	ciphertext, err := cbc.Encrypt(plaintext, block)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	// Normal decryption
	decrypted, err := cbc.Decrypt(ciphertext, block)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted[:len(plaintext)])
	// Empty data
	decrypted, err = cbc.Decrypt([]byte{}, block)
	assert.NoError(t, err)
	assert.Nil(t, decrypted)
	// Invalid length - decrypting data that is not a multiple of blockSize
	_, err = cbc.Decrypt([]byte("123"), block)
	assert.Error(t, err)
}

func TestCTRCipher_All(t *testing.T) {
	ctr := NewCTRCipher()
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	ctr.SetKey(key)
	ctr.SetIV(iv)
	assert.Equal(t, key, ctr.GetKey())
	block, _ := aes.NewCipher(key)
	plaintext := []byte("hello world!!!")
	ciphertext, err := ctr.Encrypt(plaintext, block)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	// CTR is a stream mode, decryption result should equal original text
	decrypted, err := ctr.Decrypt(ciphertext, block)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	// Empty data
	decrypted, err = ctr.Decrypt([]byte{}, block)
	assert.NoError(t, err)
	assert.Nil(t, decrypted)
}

func TestECBCipher_All(t *testing.T) {
	ecb := NewECBCipher()
	ecb.SetPadding(PKCS7)
	key := []byte("1234567890123456")
	ecb.SetKey(key)
	assert.Equal(t, key, ecb.GetKey())
	block, _ := aes.NewCipher(key)
	plaintext := []byte("hello world!!!")
	ciphertext, err := ecb.Encrypt(plaintext, block)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	decrypted, err := ecb.Decrypt(ciphertext, block)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted[:len(plaintext)])
	// Empty data
	decrypted, err = ecb.Decrypt([]byte{}, block)
	assert.NoError(t, err)
	assert.Nil(t, decrypted)
	// Invalid length - decrypting data that is not a multiple of blockSize
	_, err = ecb.Decrypt([]byte("123"), block)
	assert.Error(t, err)
}

func TestGCMCipher_All(t *testing.T) {
	gcm := NewGCMCipher()
	key := []byte("1234567890123456")
	// GCM requires 12-byte nonce
	nonce := []byte("123456789012")
	aad := []byte("aad")
	gcm.SetKey(key)
	gcm.SetNonce(nonce)
	gcm.SetAAD(aad)
	assert.Equal(t, key, gcm.GetKey())
	block, _ := aes.NewCipher(key)
	plaintext := []byte("hello world!!!")
	ciphertext, err := gcm.Encrypt(plaintext, block)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	decrypted, err := gcm.Decrypt(ciphertext, block)
	assert.NoError(t, err)
	assert.NotNil(t, decrypted)
	// Empty data
	decrypted, err = gcm.Decrypt([]byte{}, block)
	assert.NoError(t, err)
	assert.Nil(t, decrypted)
}

func TestOFBCipher_All(t *testing.T) {
	ofb := NewOFBCipher()
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	ofb.SetKey(key)
	ofb.SetIV(iv)
	assert.Equal(t, key, ofb.GetKey())
	block, _ := aes.NewCipher(key)
	plaintext := []byte("hello world!!!")
	ciphertext, err := ofb.Encrypt(plaintext, block)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	// OFB is a stream mode, decryption result should equal original text
	decrypted, err := ofb.Decrypt(ciphertext, block)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	// Empty data
	decrypted, err = ofb.Decrypt([]byte{}, block)
	assert.NoError(t, err)
	assert.Nil(t, decrypted)
}

func TestCFBCipher_All(t *testing.T) {
	cfb := NewCFBCipher()
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	cfb.SetKey(key)
	cfb.SetIV(iv)
	assert.Equal(t, key, cfb.GetKey())
	block, _ := aes.NewCipher(key)
	plaintext := []byte("hello world!!!")
	ciphertext, err := cfb.Encrypt(plaintext, block)
	assert.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	// CFB is a stream mode, decryption result should equal original text
	decrypted, err := cfb.Decrypt(ciphertext, block)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	// Empty data
	decrypted, err = cfb.Decrypt([]byte{}, block)
	assert.NoError(t, err)
	assert.Nil(t, decrypted)
}

func TestCipherConstructors(t *testing.T) {
	t.Run("NewCBCCipher", func(t *testing.T) {
		cbc := NewCBCCipher()
		assert.NotNil(t, cbc)
		assert.Equal(t, PKCS7, cbc.padding)
	})

	t.Run("NewCTRCipher", func(t *testing.T) {
		ctr := NewCTRCipher()
		assert.NotNil(t, ctr)
	})

	t.Run("NewECBCipher", func(t *testing.T) {
		ecb := NewECBCipher()
		assert.NotNil(t, ecb)
		assert.Equal(t, PKCS7, ecb.padding)
	})

	t.Run("NewGCMCipher", func(t *testing.T) {
		gcm := NewGCMCipher()
		assert.NotNil(t, gcm)
	})

	t.Run("NewOFBCipher", func(t *testing.T) {
		ofb := NewOFBCipher()
		assert.NotNil(t, ofb)
	})

	t.Run("NewCFBCipher", func(t *testing.T) {
		cfb := NewCFBCipher()
		assert.NotNil(t, cfb)
	})
}

func TestCipherSetGetMethods(t *testing.T) {
	t.Run("CBC Set/Get methods", func(t *testing.T) {
		cbc := NewCBCCipher()
		key := []byte("1234567890123456")
		iv := []byte("1234567890123456")

		cbc.SetKey(key)
		assert.Equal(t, key, cbc.GetKey())

		cbc.SetIV(iv)
		assert.Equal(t, iv, cbc.iv)

		cbc.SetPadding(Zero)
		assert.Equal(t, Zero, cbc.padding)
	})

	t.Run("CTR Set/Get methods", func(t *testing.T) {
		ctr := NewCTRCipher()
		key := []byte("1234567890123456")
		iv := []byte("1234567890123456")

		ctr.SetKey(key)
		assert.Equal(t, key, ctr.GetKey())

		ctr.SetIV(iv)
		assert.Equal(t, iv, ctr.iv)
	})

	t.Run("ECB Set/Get methods", func(t *testing.T) {
		ecb := NewECBCipher()
		key := []byte("1234567890123456")

		ecb.SetKey(key)
		assert.Equal(t, key, ecb.GetKey())

		ecb.SetPadding(Zero)
		assert.Equal(t, Zero, ecb.padding)
	})

	t.Run("GCM Set/Get methods", func(t *testing.T) {
		gcm := NewGCMCipher()
		key := []byte("1234567890123456")
		nonce := []byte("123456789012")
		aad := []byte("aad")

		gcm.SetKey(key)
		assert.Equal(t, key, gcm.GetKey())

		gcm.SetNonce(nonce)
		assert.Equal(t, nonce, gcm.nonce)

		gcm.SetAAD(aad)
		assert.Equal(t, aad, gcm.aad)
	})

	t.Run("OFB Set/Get methods", func(t *testing.T) {
		ofb := NewOFBCipher()
		key := []byte("1234567890123456")
		iv := []byte("1234567890123456")

		ofb.SetKey(key)
		assert.Equal(t, key, ofb.GetKey())

		ofb.SetIV(iv)
		assert.Equal(t, iv, ofb.iv)
	})

	t.Run("CFB Set/Get methods", func(t *testing.T) {
		cfb := NewCFBCipher()
		key := []byte("1234567890123456")
		iv := []byte("1234567890123456")

		cfb.SetKey(key)
		assert.Equal(t, key, cfb.GetKey())

		cfb.SetIV(iv)
		assert.Equal(t, iv, cfb.iv)
	})
}

func TestCipherEdgeCases(t *testing.T) {
	t.Run("CBC with empty data", func(t *testing.T) {
		cbc := NewCBCCipher()
		key := []byte("1234567890123456")
		iv := []byte("1234567890123456")
		cbc.SetKey(key)
		cbc.SetIV(iv)
		block, _ := aes.NewCipher(key)

		// Empty data encryption
		ciphertext, err := cbc.Encrypt([]byte{}, block)
		assert.NoError(t, err)
		assert.NotEmpty(t, ciphertext) // Should be padded

		// Empty data decryption
		decrypted, err := cbc.Decrypt([]byte{}, block)
		assert.NoError(t, err)
		assert.Nil(t, decrypted)
	})

	t.Run("ECB with empty data", func(t *testing.T) {
		ecb := NewECBCipher()
		key := []byte("1234567890123456")
		ecb.SetKey(key)
		block, _ := aes.NewCipher(key)

		// Empty data encryption
		ciphertext, err := ecb.Encrypt([]byte{}, block)
		assert.NoError(t, err)
		assert.NotEmpty(t, ciphertext) // Should be padded

		// Empty data decryption
		decrypted, err := ecb.Decrypt([]byte{}, block)
		assert.NoError(t, err)
		assert.Nil(t, decrypted)
	})

	t.Run("Stream ciphers with empty data", func(t *testing.T) {
		key := []byte("1234567890123456")
		iv := []byte("1234567890123456")
		block, _ := aes.NewCipher(key)

		// CTR
		ctr := NewCTRCipher()
		ctr.SetKey(key)
		ctr.SetIV(iv)
		ciphertext, err := ctr.Encrypt([]byte{}, block)
		assert.NoError(t, err)
		assert.Empty(t, ciphertext) // Stream mode empty data produces no output

		// OFB
		ofb := NewOFBCipher()
		ofb.SetKey(key)
		ofb.SetIV(iv)
		ciphertext, err = ofb.Encrypt([]byte{}, block)
		assert.NoError(t, err)
		assert.Empty(t, ciphertext)

		// CFB
		cfb := NewCFBCipher()
		cfb.SetKey(key)
		cfb.SetIV(iv)
		ciphertext, err = cfb.Encrypt([]byte{}, block)
		assert.NoError(t, err)
		assert.Empty(t, ciphertext)
	})

	t.Run("CBC with padding error", func(t *testing.T) {
		cbc := NewCBCCipher()
		key := []byte("1234567890123456")
		iv := []byte("1234567890123456")
		cbc.SetKey(key)
		cbc.SetIV(iv)
		// Using a padding mode that would result in length not being a multiple of blockSize
		cbc.SetPadding(No) // No padding won't pad data
		block, _ := aes.NewCipher(key)

		// Using data that is not a multiple of blockSize, No padding won't pad, should trigger error
		_, err := cbc.Encrypt([]byte("123"), block)
		assert.Error(t, err)
	})

	t.Run("ECB with padding error", func(t *testing.T) {
		ecb := NewECBCipher()
		key := []byte("1234567890123456")
		ecb.SetKey(key)
		// Using a padding mode that would result in length not being a multiple of blockSize
		ecb.SetPadding(No) // No padding won't pad data
		block, _ := aes.NewCipher(key)

		// Using data that is not a multiple of blockSize, No padding won't pad, should trigger error
		_, err := ecb.Encrypt([]byte("123"), block)
		assert.Error(t, err)
	})

	t.Run("CBC decrypt with error", func(t *testing.T) {
		cbc := NewCBCCipher()
		key := []byte("1234567890123456")
		iv := []byte("1234567890123456")
		cbc.SetKey(key)
		cbc.SetIV(iv)
		block, _ := aes.NewCipher(key)

		// Normal encryption
		plaintext := []byte("hello world!!!")
		ciphertext, err := cbc.Encrypt(plaintext, block)
		assert.NoError(t, err)

		// Simulate decryption error - using wrong IV
		cbc.SetIV([]byte("wrong iv length!!"))
		_, err = cbc.Decrypt(ciphertext, block)
		assert.Error(t, err)
	})
}
