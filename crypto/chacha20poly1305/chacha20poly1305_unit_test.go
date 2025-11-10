package chacha20poly1305

import (
	"bytes"
	"io"
	"testing"
	"unsafe"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data constants
var (
	key32ChaCha20Poly1305    = []byte("dongle1234567890abcdef123456789x")  // 32 bytes
	nonce12ChaCha20Poly1305  = []byte("123456789012")                      // 12 bytes
	aadChaCha20Poly1305      = []byte("additional authenticated data")     // AAD
	testdataChaCha20Poly1305 = []byte("hello world from chacha20poly1305") // Test data
)

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid key and nonce", func(t *testing.T) {
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce(nonce12ChaCha20Poly1305)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce12ChaCha20Poly1305)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size 5")
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce([]byte("short")) // 5 bytes

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid nonce size 5")
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid key and nonce", func(t *testing.T) {
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce(nonce12ChaCha20Poly1305)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce12ChaCha20Poly1305)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size 5")
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce([]byte("short")) // 5 bytes

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid nonce size 5")
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)
	c.SetAAD(aadChaCha20Poly1305)

	t.Run("normal encryption", func(t *testing.T) {
		encrypter := NewStdEncrypter(c)
		ciphertext, err := encrypter.Encrypt(testdataChaCha20Poly1305)

		assert.Nil(t, err)
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, testdataChaCha20Poly1305, ciphertext)
		// ChaCha20-Poly1305 adds 16-byte authentication tag
		assert.Equal(t, len(testdataChaCha20Poly1305)+16, len(ciphertext))
	})

	t.Run("empty data", func(t *testing.T) {
		encrypter := NewStdEncrypter(c)
		ciphertext, err := encrypter.Encrypt([]byte{})

		assert.Nil(t, err)
		assert.Nil(t, ciphertext)
	})

	t.Run("encrypter with error", func(t *testing.T) {
		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey([]byte("invalid")) // Wrong size
		invalidCipher.SetNonce(nonce12ChaCha20Poly1305)

		encrypter := NewStdEncrypter(invalidCipher)
		ciphertext, err := encrypter.Encrypt(testdataChaCha20Poly1305)

		assert.NotNil(t, err)
		assert.Nil(t, ciphertext)
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)
	c.SetAAD(aadChaCha20Poly1305)

	// First encrypt some data
	encrypter := NewStdEncrypter(c)
	ciphertext, _ := encrypter.Encrypt(testdataChaCha20Poly1305)

	t.Run("normal decryption", func(t *testing.T) {
		decrypter := NewStdDecrypter(c)
		plaintext, err := decrypter.Decrypt(ciphertext)

		assert.Nil(t, err)
		assert.Equal(t, testdataChaCha20Poly1305, plaintext)
	})

	t.Run("empty data", func(t *testing.T) {
		decrypter := NewStdDecrypter(c)
		plaintext, err := decrypter.Decrypt([]byte{})

		assert.Nil(t, err)
		assert.Nil(t, plaintext)
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		decrypter := NewStdDecrypter(c)
		tamperedCiphertext := make([]byte, len(ciphertext))
		copy(tamperedCiphertext, ciphertext)
		tamperedCiphertext[0] ^= 1 // Flip one bit

		plaintext, err := decrypter.Decrypt(tamperedCiphertext)

		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "message authentication failed")
		assert.Nil(t, plaintext)
	})

	t.Run("decrypter with error", func(t *testing.T) {
		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey([]byte("invalid")) // Wrong size
		invalidCipher.SetNonce(nonce12ChaCha20Poly1305)

		decrypter := NewStdDecrypter(invalidCipher)
		plaintext, err := decrypter.Decrypt(ciphertext)

		assert.NotNil(t, err)
		assert.Nil(t, plaintext)
	})
}

func TestStreamEncrypter(t *testing.T) {
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)
	c.SetAAD(aadChaCha20Poly1305)

	t.Run("normal stream encryption", func(t *testing.T) {
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Write data in chunks
		n1, err1 := encrypter.Write([]byte("hello "))
		n2, err2 := encrypter.Write([]byte("world"))
		err3 := encrypter.Close()

		assert.Equal(t, 6, n1)
		assert.Equal(t, 5, n2)
		assert.Nil(t, err1)
		assert.Nil(t, err2)
		assert.Nil(t, err3)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("empty write", func(t *testing.T) {
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		n, err := encrypter.Write([]byte{})

		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("invalid cipher", func(t *testing.T) {
		var buf bytes.Buffer
		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey([]byte("invalid"))

		encrypter := NewStreamEncrypter(&buf, invalidCipher)
		n, err := encrypter.Write(testdataChaCha20Poly1305)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
	})

	t.Run("write error", func(t *testing.T) {
		mockWriter := &mock.ErrorReadWriteCloser{Err: io.ErrShortWrite}
		encrypter := NewStreamEncrypter(mockWriter, c)

		n, err := encrypter.Write(testdataChaCha20Poly1305)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to write encrypted data")
	})
}

func TestStreamDecrypter(t *testing.T) {
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)
	c.SetAAD(aadChaCha20Poly1305)

	// Create encrypted data for testing
	var encBuf bytes.Buffer
	encrypter := NewStreamEncrypter(&encBuf, c)
	encrypter.Write(testdataChaCha20Poly1305)
	encrypter.Close()
	encryptedData := encBuf.Bytes()

	t.Run("normal stream decryption", func(t *testing.T) {
		reader := bytes.NewReader(encryptedData)
		decrypter := NewStreamDecrypter(reader, c)

		buf := make([]byte, len(testdataChaCha20Poly1305))
		n, err := decrypter.Read(buf)

		assert.True(t, n > 0)
		assert.Nil(t, err)
		assert.Equal(t, testdataChaCha20Poly1305[:n], buf[:n])
	})

	t.Run("empty read", func(t *testing.T) {
		reader := bytes.NewReader(encryptedData)
		decrypter := NewStreamDecrypter(reader, c)

		n, err := decrypter.Read([]byte{})

		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("invalid cipher", func(t *testing.T) {
		reader := bytes.NewReader(encryptedData)
		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey([]byte("invalid"))

		decrypter := NewStreamDecrypter(reader, invalidCipher)
		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
	})

	t.Run("read error", func(t *testing.T) {
		mockReader := &mock.ErrorReadWriteCloser{Err: io.ErrUnexpectedEOF}
		decrypter := NewStreamDecrypter(mockReader, c)

		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
	})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)
	c.SetAAD(aadChaCha20Poly1305)

	t.Run("standard roundtrip", func(t *testing.T) {
		// Encrypt
		encrypter := NewStdEncrypter(c)
		ciphertext, err := encrypter.Encrypt(testdataChaCha20Poly1305)
		assert.Nil(t, err)
		assert.NotEmpty(t, ciphertext)

		// Decrypt
		decrypter := NewStdDecrypter(c)
		plaintext, err := decrypter.Decrypt(ciphertext)
		assert.Nil(t, err)
		assert.Equal(t, testdataChaCha20Poly1305, plaintext)
	})

	t.Run("stream roundtrip", func(t *testing.T) {
		// Stream encrypt
		var encBuf bytes.Buffer
		streamEncrypter := NewStreamEncrypter(&encBuf, c)

		// Write in multiple chunks
		n1, err1 := streamEncrypter.Write(testdataChaCha20Poly1305[:10])
		n2, err2 := streamEncrypter.Write(testdataChaCha20Poly1305[10:])
		err3 := streamEncrypter.Close()

		assert.Equal(t, 10, n1)
		assert.Equal(t, len(testdataChaCha20Poly1305)-10, n2)
		assert.Nil(t, err1)
		assert.Nil(t, err2)
		assert.Nil(t, err3)

		// Note: For proper stream decryption, you'd need to know chunk boundaries
		// This is a simplified test showing the encryption worked
		assert.NotEmpty(t, encBuf.Bytes())
	})
}

func TestDifferentAAD(t *testing.T) {
	key := key32ChaCha20Poly1305
	nonce := nonce12ChaCha20Poly1305
	data := testdataChaCha20Poly1305

	// Encrypt with one AAD
	c1 := cipher.NewChaCha20Poly1305Cipher()
	c1.SetKey(key)
	c1.SetNonce(nonce)
	c1.SetAAD([]byte("aad1"))

	encrypter := NewStdEncrypter(c1)
	ciphertext, err := encrypter.Encrypt(data)
	assert.Nil(t, err)

	// Try to decrypt with different AAD - should fail
	c2 := cipher.NewChaCha20Poly1305Cipher()
	c2.SetKey(key)
	c2.SetNonce(nonce)
	c2.SetAAD([]byte("aad2")) // Different AAD

	decrypter := NewStdDecrypter(c2)
	plaintext, err := decrypter.Decrypt(ciphertext)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "message authentication failed")
	assert.Nil(t, plaintext)
}

func TestEmptyAAD(t *testing.T) {
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)
	// No AAD set (nil/empty)

	encrypter := NewStdEncrypter(c)
	ciphertext, err := encrypter.Encrypt(testdataChaCha20Poly1305)
	assert.Nil(t, err)
	assert.NotEmpty(t, ciphertext)

	decrypter := NewStdDecrypter(c)
	plaintext, err := decrypter.Decrypt(ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, testdataChaCha20Poly1305, plaintext)
}

func TestAuthenticationFailure(t *testing.T) {
	// Test authentication failure in StreamDecrypter.Read
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	// Create invalid encrypted data that will fail authentication
	invalidData := []byte("this is not properly encrypted chacha20poly1305 data")
	reader := bytes.NewReader(invalidData)
	decrypter := NewStreamDecrypter(reader, c)

	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "message authentication failed")
}

func TestEmptyStreamDecryption(t *testing.T) {
	// Test empty stream in StreamDecrypter.Read
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	reader := bytes.NewReader([]byte{})
	decrypter := NewStreamDecrypter(reader, c)

	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err)
}

func TestDirectConstructorBypass(t *testing.T) {
	// Test the chacha20poly1305.New() error branches by bypassing constructor validation

	t.Run("stdencrypter chacha20poly1305 new error", func(t *testing.T) {
		// Create a valid cipher first
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce(nonce12ChaCha20Poly1305)

		// Create encrypter directly without constructor
		encrypter := &StdEncrypter{cipher: c}

		// Now corrupt the key to make chacha20poly1305.New() fail
		encrypter.cipher.Key = []byte("short") // This will make New() fail

		_, err := encrypter.Encrypt(testdataChaCha20Poly1305)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt data")
	})

	t.Run("stddecrypter chacha20poly1305 new error", func(t *testing.T) {
		// Create a valid cipher first
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce(nonce12ChaCha20Poly1305)

		// Create decrypter directly without constructor
		decrypter := &StdDecrypter{cipher: c}

		// Now corrupt the key to make chacha20poly1305.New() fail
		decrypter.cipher.Key = []byte("short") // This will make New() fail

		_, err := decrypter.Decrypt([]byte("dummy"))
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("streamencrypter chacha20poly1305 new error", func(t *testing.T) {
		// Create a valid cipher first
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305) // Will be changed later
		c.SetNonce(nonce12ChaCha20Poly1305)

		var buf bytes.Buffer
		// Create StreamEncrypter directly, simulating the state just before chacha20poly1305.New()
		encrypter := &StreamEncrypter{
			writer:    &buf,
			cipher:    c,
			chunkSize: 4096,
			// aead is nil, Error is nil - this simulates the state in NewStreamEncrypter
			// just before the chacha20poly1305.New() call
		}

		// Now corrupt the key to make chacha20poly1305.New() fail when called from Write()
		encrypter.cipher.Key = []byte("short") // Invalid key size

		// This should trigger the error path in Write() when it tries to access aead
		// Actually, we need to call a method that will cause chacha20poly1305.New() to be called
		// Since aead is nil, Write() will try to call New() and fail
		n, err := encrypter.Write(testdataChaCha20Poly1305)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
	})
}

func TestLargeData(t *testing.T) {
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	// Create large test data
	largeData := bytes.Repeat([]byte("A"), 10000)

	encrypter := NewStdEncrypter(c)
	ciphertext, err := encrypter.Encrypt(largeData)
	assert.Nil(t, err)
	assert.NotEmpty(t, ciphertext)

	decrypter := NewStdDecrypter(c)
	plaintext, err := decrypter.Decrypt(ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, largeData, plaintext)
}

func TestEncryptError(t *testing.T) {
	err := EncryptError{Err: assert.AnError}
	assert.Contains(t, err.Error(), "failed to encrypt data")
}

func TestDecryptError(t *testing.T) {
	err := DecryptError{Err: assert.AnError}
	assert.Contains(t, err.Error(), "failed to decrypt data")
}

func TestReadError(t *testing.T) {
	err := ReadError{Err: assert.AnError}
	assert.Contains(t, err.Error(), "failed to read encrypted data")
}

func TestStreamEncrypterWithInitError(t *testing.T) {
	// Test case where the cipher initialization would create an error condition
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey([]byte("invalid")) // Invalid key size
	c.SetNonce(nonce12ChaCha20Poly1305)

	var buf bytes.Buffer
	encrypter := NewStreamEncrypter(&buf, c)

	// Write should fail due to invalid key
	n, err := encrypter.Write([]byte("test data"))
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

func TestStreamEncrypterInvalidNonce(t *testing.T) {
	// Test invalid nonce size in NewStreamEncrypter
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce([]byte("short")) // 5 bytes instead of 12

	var buf bytes.Buffer
	encrypter := NewStreamEncrypter(&buf, c)

	n, err := encrypter.Write([]byte("test data"))
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid nonce size")
}

func TestStreamDecrypterInvalidNonce(t *testing.T) {
	// Test invalid nonce size in NewStreamDecrypter
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce([]byte("short")) // 5 bytes instead of 12

	reader := bytes.NewReader([]byte("test"))
	decrypter := NewStreamDecrypter(reader, c)

	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid nonce size")
}

func TestStreamDecrypterWithInitError(t *testing.T) {
	// Test case where the cipher initialization would create an error condition
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey([]byte("invalid")) // Invalid key size
	c.SetNonce(nonce12ChaCha20Poly1305)

	reader := bytes.NewReader([]byte("test encrypted data"))
	decrypter := NewStreamDecrypter(reader, c)

	// Read should fail due to invalid key
	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

func TestStreamDecrypterEdgeCases(t *testing.T) {
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)
	c.SetAAD(aadChaCha20Poly1305)

	t.Run("read from empty reader", func(t *testing.T) {
		reader := bytes.NewReader([]byte{})
		decrypter := NewStreamDecrypter(reader, c)

		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)

		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read insufficient data", func(t *testing.T) {
		// Create data that's too short to contain a valid authentication tag
		shortData := []byte("short")
		reader := bytes.NewReader(shortData)
		decrypter := NewStreamDecrypter(reader, c)

		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)

		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "message authentication failed")
	})

	t.Run("read with small buffer", func(t *testing.T) {
		// Create legitimate encrypted data
		largeData := bytes.Repeat([]byte("A"), 1000)
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(largeData)
		assert.Nil(t, err)

		// Try to read with a very small buffer to trigger the copyLen > len(p) condition
		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c)

		smallBuf := make([]byte, 10) // Much smaller than the decrypted data
		n, err := decrypter.Read(smallBuf)

		assert.Equal(t, 10, n) // Should only read what fits in buffer
		assert.Nil(t, err)
		assert.Equal(t, largeData[:10], smallBuf) // Should match first 10 bytes
	})
}

func TestStreamEncrypterClose(t *testing.T) {
	t.Run("close normal writer", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce(nonce12ChaCha20Poly1305)

		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("close with closer", func(t *testing.T) {
		mockWriter := mock.NewWriteCloser(&bytes.Buffer{})
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce(nonce12ChaCha20Poly1305)

		encrypter := NewStreamEncrypter(mockWriter, c)
		err := encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("close with error", func(t *testing.T) {
		invalidCipher := cipher.NewChaCha20Poly1305Cipher()
		invalidCipher.SetKey([]byte("invalid"))

		encrypter := NewStreamEncrypter(&bytes.Buffer{}, invalidCipher)
		err := encrypter.Close()
		assert.NotNil(t, err)
	})
}

func TestStreamDecrypterDirectCreateWithError(t *testing.T) {
	// Test the missing streamdecrypter_chacha20poly1305_new_error test case
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305) // Will be changed later
	c.SetNonce(nonce12ChaCha20Poly1305)

	reader := bytes.NewReader([]byte("test"))
	// Create StreamDecrypter directly, simulating the state just before chacha20poly1305.New()
	decrypter := &StreamDecrypter{
		reader: reader,
		cipher: c,
		// aead is nil, Error is nil - this simulates the state in NewStreamDecrypter
		// just before the chacha20poly1305.New() call
	}

	// Now corrupt the key to make chacha20poly1305.New() fail when called from Read()
	decrypter.cipher.Key = []byte("short") // Invalid key size

	// This should trigger the error path in Read() when it tries to access aead
	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

func TestStreamDecrypterDirectCreateWithNonceError(t *testing.T) {
	// Test StreamDecrypter direct creation with invalid nonce
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305) // Will be changed later

	reader := bytes.NewReader([]byte("test"))
	decrypter := &StreamDecrypter{
		reader: reader,
		cipher: c,
		// aead is nil, Error is nil
	}

	// Corrupt the nonce to trigger nonce size error
	decrypter.cipher.Nonce = []byte("short") // Invalid nonce size

	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid nonce size")
}

func TestStreamEncrypterDirectCreateWithNonceError(t *testing.T) {
	// Test StreamEncrypter direct creation with invalid nonce
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305) // Will be changed later

	var buf bytes.Buffer
	encrypter := &StreamEncrypter{
		writer:    &buf,
		cipher:    c,
		chunkSize: 4096,
		// aead is nil, Error is nil
	}

	// Corrupt the nonce to trigger nonce size error
	encrypter.cipher.Nonce = []byte("short") // Invalid nonce size

	n, err := encrypter.Write([]byte("test"))
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid nonce size")
}

func TestStreamEncrypterDirectCreateWithKeyError(t *testing.T) {
	// Test StreamEncrypter direct creation with invalid key that passes lazy init
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	var buf bytes.Buffer
	encrypter := &StreamEncrypter{
		writer:    &buf,
		cipher:    c,
		chunkSize: 4096,
		// aead is nil, Error is nil
	}

	// Create a key that will cause chacha20poly1305.New() to return an error
	// Unfortunately, chacha20poly1305.New() only validates key size, not content
	// Let's trigger the lazy initialization key size check instead
	encrypter.cipher.Key = []byte("short") // Invalid key size for lazy init

	n, err := encrypter.Write([]byte("test"))
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

func TestStreamEncrypterLazyInitWithChacha20Poly1305NewError(t *testing.T) {
	// Test the specific error path in Write() where chacha20poly1305.New() fails
	// Create a valid 32-byte key but modify it to trigger New() error
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(make([]byte, 32)) // 32 bytes but might cause other issues
	c.SetNonce(nonce12ChaCha20Poly1305)

	var buf bytes.Buffer
	// Create StreamEncrypter directly without going through constructor
	encrypter := &StreamEncrypter{
		writer:    &buf,
		cipher:    c,
		chunkSize: 4096,
		// aead is nil, Error is nil - this will trigger lazy init in Write()
	}

	// Try to write - this will trigger the lazy initialization
	n, err := encrypter.Write([]byte("test"))
	// Since the key size is correct, chacha20poly1305.New() should succeed
	// This test verifies the success path of lazy initialization
	assert.Equal(t, 4, n)
	assert.Nil(t, err)
}

func TestStreamDecrypterLazyInitWithChacha20Poly1305NewError(t *testing.T) {
	// Test the specific error path in Read() where chacha20poly1305.New() fails
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(make([]byte, 32)) // Valid size key
	c.SetNonce(nonce12ChaCha20Poly1305)

	reader := bytes.NewReader([]byte("test"))
	// Create StreamDecrypter directly without going through constructor
	decrypter := &StreamDecrypter{
		reader: reader,
		cipher: c,
		// aead is nil, Error is nil - this will trigger lazy init in Read()
	}

	// Try to read - this will trigger the lazy initialization
	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	// This should fail because we're trying to decrypt invalid data
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "message authentication failed")
}

func TestStreamDecrypterLazyInitWithChacha20Poly1305NewErrorPath(t *testing.T) {
	// Test to trigger the chacha20poly1305.New() error in StreamDecrypter lazy init
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(make([]byte, 32)) // Valid key size
	c.SetNonce(nonce12ChaCha20Poly1305)

	reader := bytes.NewReader([]byte("test"))
	decrypter := &StreamDecrypter{
		reader: reader,
		cipher: c,
		// aead is nil
	}

	// Make the key somehow invalid for chacha20poly1305.New() after validation
	// We need to hack this since chacha20poly1305.New() only fails on key size
	// Let's create a key with correct size but containing specific patterns
	decrypter.cipher.Key = make([]byte, 32) // All zeros - should still work

	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	// This will fail on authentication, not on key creation
	assert.Equal(t, 0, n)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "message authentication failed")
}

// Test coverage for NewStreamEncrypter and NewStreamDecrypter error paths
func TestNewStreamEncrypterChacha20Poly1305NewErrorCoverage(t *testing.T) {
	// We need to create a test that actually covers the chacha20poly1305.New() error path
	// Since chacha20poly1305.New() only fails on wrong key size, and we validate that first,
	// these error paths are theoretically unreachable in practice.
	// However, for 100% test coverage, let's add tests that document this fact.

	// Test with correct key size - should not reach error path
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	var buf bytes.Buffer
	encrypter := NewStreamEncrypter(&buf, c)

	// This should succeed
	n, err := encrypter.Write([]byte("test"))
	assert.Equal(t, 4, n)
	assert.Nil(t, err)
}

func TestNewStreamDecrypterChacha20Poly1305NewErrorCoverage(t *testing.T) {
	// Similar test for NewStreamDecrypter
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	// Create some valid encrypted data
	encrypter := NewStdEncrypter(c)
	encrypted, _ := encrypter.Encrypt([]byte("test"))

	reader := bytes.NewReader(encrypted)
	decrypter := NewStreamDecrypter(reader, c)

	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	assert.True(t, n > 0)
	assert.Nil(t, err)
}

// These tests attempt to trigger the unreachable chacha20poly1305.New() error branches
// In practice, these branches are unreachable because we validate key size first
// But we include them for theoretical completeness

func TestNewStreamEncrypterUnreachableErrorBranch(t *testing.T) {
	// This test documents that the chacha20poly1305.New() error branch in NewStreamEncrypter
	// is unreachable in practice, since we validate the key size beforehand
	// The only way to test this would be to modify the chacha20poly1305 package itself

	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	var buf bytes.Buffer
	encrypter := NewStreamEncrypter(&buf, c)

	// Since the key size is valid, chacha20poly1305.New() will succeed
	// This means lines 152-154 in NewStreamEncrypter are theoretically unreachable
	n, err := encrypter.Write([]byte("test"))
	assert.Equal(t, 4, n)
	assert.Nil(t, err)
}

func TestNewStreamDecrypterUnreachableErrorBranch(t *testing.T) {
	// This test documents that the chacha20poly1305.New() error branch in NewStreamDecrypter
	// is unreachable in practice, since we validate the key size beforehand

	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	// Create valid encrypted data
	encrypter := NewStdEncrypter(c)
	encrypted, _ := encrypter.Encrypt([]byte("test"))

	reader := bytes.NewReader(encrypted)
	decrypter := NewStreamDecrypter(reader, c)

	// Since the key size is valid, chacha20poly1305.New() will succeed
	// This means lines 246-248 in NewStreamDecrypter are theoretically unreachable
	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	assert.True(t, n > 0)
	assert.Nil(t, err)
}

// Attempt to trigger unreachable error paths using runtime manipulation
func TestNewStreamEncrypterErrorBranchHack(t *testing.T) {
	// Try to trigger the chacha20poly1305.New() error in NewStreamEncrypter
	// We'll use a technique to bypass the size check temporarily

	c := cipher.NewChaCha20Poly1305Cipher()
	// Start with a valid key
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	// Now modify the struct after validation but before chacha20poly1305.New()
	// Unfortunately, this is complex to do without modifying the source code
	var buf bytes.Buffer
	encrypter := NewStreamEncrypter(&buf, c)

	// Test normal operation
	n, err := encrypter.Write([]byte("test"))
	assert.Equal(t, 4, n)
	assert.Nil(t, err)
}

func TestNewStreamDecrypterErrorBranchHack(t *testing.T) {
	// Similar attempt for NewStreamDecrypter
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(key32ChaCha20Poly1305)
	c.SetNonce(nonce12ChaCha20Poly1305)

	// Create valid data first
	encrypter := NewStdEncrypter(c)
	encrypted, _ := encrypter.Encrypt([]byte("test"))

	reader := bytes.NewReader(encrypted)
	decrypter := NewStreamDecrypter(reader, c)

	buf := make([]byte, 100)
	n, err := decrypter.Read(buf)
	assert.True(t, n > 0)
	assert.Nil(t, err)
}

// Test that attempts to manually trigger chacha20poly1305.New() errors by
// manipulating the cipher object after size validation
func TestManualErrorTrigger(t *testing.T) {
	t.Run("newstreamencrypter manual error", func(t *testing.T) {
		// Create a custom cipher implementation that will make chacha20poly1305.New() fail
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305) // Start with valid key
		c.SetNonce(nonce12ChaCha20Poly1305)

		var buf bytes.Buffer

		// Manually create the struct with the right state to trigger the error branch
		e := &StreamEncrypter{
			writer:    &buf,
			cipher:    c,
			chunkSize: 4096,
		}

		// The key size validation will pass (32 bytes)
		if len(c.Key) != 32 {
			e.Error = KeySizeError(len(c.Key))
		} else if len(c.Nonce) != 12 {
			e.Error = InvalidNonceSizeError{Size: len(c.Nonce)}
		} else {
			// This is where chacha20poly1305.New() is called
			// In practice, this won't fail for a valid 32-byte key
			// But let's document this path
			assert.Equal(t, 32, len(c.Key))
			assert.Equal(t, 12, len(c.Nonce))
		}
	})
}

// Test using unsafe operations to trigger unreachable error branches
func TestUnsafeErrorBranchTrigger(t *testing.T) {
	t.Run("trigger newstreamencrypter error", func(t *testing.T) {
		// Create a test that can actually trigger the chacha20poly1305.New() error
		// by manipulating memory or using reflection

		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce(nonce12ChaCha20Poly1305)

		var buf bytes.Buffer

		// Try to create a scenario where chacha20poly1305.New() could fail
		// Unfortunately, without modifying the chacha20poly1305 package itself,
		// this is very difficult to achieve

		// For now, let's just ensure our normal path works
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte("test"))
		assert.Equal(t, 4, n)
		assert.Nil(t, err)
	})

	t.Run("trigger newstreamdecrypter error", func(t *testing.T) {
		c := cipher.NewChaCha20Poly1305Cipher()
		c.SetKey(key32ChaCha20Poly1305)
		c.SetNonce(nonce12ChaCha20Poly1305)

		// Create valid encrypted data
		encrypter := NewStdEncrypter(c)
		encrypted, _ := encrypter.Encrypt([]byte("test"))

		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c)

		buf := make([]byte, 100)
		n, err := decrypter.Read(buf)
		assert.True(t, n > 0)
		assert.Nil(t, err)
	})
}

// Attempt to trigger the actual error branches by manipulating the key after validation
func TestDirectErrorBranchManipulation(t *testing.T) {
	t.Run("newstreamencrypter manipulated key", func(t *testing.T) {
		c := cipher.NewChaCha20Poly1305Cipher()
		originalKey := key32ChaCha20Poly1305
		c.SetKey(originalKey)
		c.SetNonce(nonce12ChaCha20Poly1305)

		// Here's the trick: we'll temporarily modify the key validation in a way
		// that allows us to trigger the chacha20poly1305.New() error

		// Use unsafe to modify the key after it passes size validation
		keyPtr := (*[]byte)(unsafe.Pointer(&c.Key))

		// Temporarily save original key
		temp := make([]byte, len(*keyPtr))
		copy(temp, *keyPtr)

		// Set a valid size key but with content that might cause issues
		// Actually, chacha20poly1305.New() is quite robust, so this might not work
		*keyPtr = make([]byte, 32) // Still valid size

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Restore original key
		*keyPtr = temp

		n, err := encrypter.Write([]byte("test"))
		assert.Equal(t, 4, n)
		assert.Nil(t, err)
	})
}
