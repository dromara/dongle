package triple_des

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for CTR mode
var (
	ctrKey16    = []byte("1234567890123456")         // 16-byte key for 2-key 3DES
	ctrKey24    = []byte("123456789012345678901234") // 24-byte key for 3-key 3DES
	ctrNonce8   = []byte("12345678")                 // 8-byte nonce for CTR
	ctrTestData = []byte("hello world")

	// Expected encrypted results for "hello world" (verified with Python pycryptodome library)
	ctrHexEncrypted16    = "d43264d06ddec8402835c5"                                                 // Hex encoded encrypted data (16-byte key)
	ctrBase64Encrypted16 = "1DJk0G3eyEAoNcU="                                                       // Base64 encoded encrypted data (16-byte key)
	ctrRawEncrypted16    = []byte{0xd4, 0x32, 0x64, 0xd0, 0x6d, 0xde, 0xc8, 0x40, 0x28, 0x35, 0xc5} // Raw encrypted bytes (16-byte key)

	ctrHexEncrypted24    = "75b06559d8227f24d5862c"                                                 // Hex encoded encrypted data (24-byte key)
	ctrBase64Encrypted24 = "dbBlWdgifyTVhiw="                                                       // Base64 encoded encrypted data (24-byte key)
	ctrRawEncrypted24    = []byte{0x75, 0xb0, 0x65, 0x59, 0xd8, 0x22, 0x7f, 0x24, 0xd5, 0x86, 0x2c} // Raw encrypted bytes (24-byte key)
)

func TestNewStdEncrypter_CTR(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		validKeys := [][]byte{ctrKey16, ctrKey24}
		for _, key := range validKeys {
			c := cipher.New3DesCipher(cipher.CTR)
			c.SetKey(key)
			c.SetIV(ctrNonce8)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.Nil(t, encrypter.Error)
			assert.Equal(t, *c, encrypter.cipher)
		}
	})

	t.Run("invalid key sizes", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("8byteskey"),
			[]byte("15byteskey!!"),
			make([]byte, 17),
			make([]byte, 25),
		}
		for _, key := range invalidKeys {
			c := cipher.New3DesCipher(cipher.CTR)
			c.SetKey(key)
			c.SetIV(ctrNonce8)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.NotNil(t, encrypter.Error)
		}
	})
}

func TestStdEncrypter_Encrypt_CTR(t *testing.T) {
	t.Run("encrypt with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ctrTestData)

		assert.Nil(t, err)
		assert.Equal(t, ctrRawEncrypted16, result)

		// Verify hex encoding
		hexResult := hex.EncodeToString(result)
		assert.Equal(t, ctrHexEncrypted16, hexResult)

		// Verify base64 encoding
		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, ctrBase64Encrypted16, base64Result)
	})

	t.Run("encrypt with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey24)
		c.SetIV(ctrNonce8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ctrTestData)

		assert.Nil(t, err)
		assert.Equal(t, ctrRawEncrypted24, result)

		// Verify hex encoding
		hexResult := hex.EncodeToString(result)
		assert.Equal(t, ctrHexEncrypted24, hexResult)

		// Verify base64 encoding
		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, ctrBase64Encrypted24, base64Result)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt([]byte{})

		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("encrypt nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(nil)

		assert.Nil(t, err)
		assert.Nil(t, result)
	})
}

func TestStdDecrypter_Decrypt_CTR(t *testing.T) {
	t.Run("decrypt with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(ctrRawEncrypted16)

		assert.Nil(t, err)
		assert.Equal(t, ctrTestData, result)
	})

	t.Run("decrypt with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey24)
		c.SetIV(ctrNonce8)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(ctrRawEncrypted24)

		assert.Nil(t, err)
		assert.Equal(t, ctrTestData, result)
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt([]byte{})

		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("decrypt nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(nil)

		assert.Nil(t, err)
		assert.Nil(t, result)
	})
}

func TestStreamEncrypter_Write_CTR(t *testing.T) {
	t.Run("write data to stream encrypter with 16-byte key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(ctrTestData)

		assert.Nil(t, err)
		assert.Equal(t, len(ctrTestData), n)
		assert.Equal(t, ctrRawEncrypted16, buf.Bytes())
	})

	t.Run("write data to stream encrypter with 24-byte key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey24)
		c.SetIV(ctrNonce8)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(ctrTestData)

		assert.Nil(t, err)
		assert.Equal(t, len(ctrTestData), n)
		assert.Equal(t, ctrRawEncrypted24, buf.Bytes())
	})

	t.Run("write empty data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})

		assert.Nil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, []byte(nil), buf.Bytes())
	})

	t.Run("write nil data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(nil)

		assert.Nil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, []byte(nil), buf.Bytes())
	})
}

func TestStreamDecrypter_Read_CTR(t *testing.T) {
	t.Run("read data from stream decrypter with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		decrypter := NewStreamDecrypter(bytes.NewReader(ctrRawEncrypted16), c)
		buf := make([]byte, len(ctrTestData))
		n, err := decrypter.Read(buf)

		assert.Nil(t, err)
		assert.Equal(t, len(ctrTestData), n)
		assert.Equal(t, ctrTestData, buf)
	})

	t.Run("read data from stream decrypter with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey24)
		c.SetIV(ctrNonce8)

		decrypter := NewStreamDecrypter(bytes.NewReader(ctrRawEncrypted24), c)
		buf := make([]byte, len(ctrTestData))
		n, err := decrypter.Read(buf)

		assert.Nil(t, err)
		assert.Equal(t, len(ctrTestData), n)
		assert.Equal(t, ctrTestData, buf)
	})

	t.Run("read empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		decrypter := NewStreamDecrypter(bytes.NewReader([]byte{}), c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)

		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		decrypter := NewStreamDecrypter(bytes.NewReader(nil), c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)

		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamEncrypter_Close_CTR(t *testing.T) {
	t.Run("close stream encrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()

		assert.Nil(t, err)
	})
}

func TestStreamEncrypter_Write_Error_CTR(t *testing.T) {
	t.Run("write error", func(t *testing.T) {
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("write error"))
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStreamEncrypter(mockWriter, c)
		n, err := encrypter.Write(ctrTestData)

		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamDecrypter_Read_Error_CTR(t *testing.T) {
	t.Run("read error", func(t *testing.T) {
		mockReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)

		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamEncrypter_Close_Error_CTR(t *testing.T) {
	t.Run("close error", func(t *testing.T) {
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("close error"))
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStreamEncrypter(mockWriter, c)
		err := encrypter.Close()

		assert.NotNil(t, err)
	})
}

func TestCTR_EncodingFormats(t *testing.T) {
	t.Run("verify hex encoding with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ctrTestData)
		assert.Nil(t, err)

		hexResult := hex.EncodeToString(result)
		assert.Equal(t, ctrHexEncrypted16, hexResult)
	})

	t.Run("verify base64 encoding with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey16)
		c.SetIV(ctrNonce8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ctrTestData)
		assert.Nil(t, err)

		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, ctrBase64Encrypted16, base64Result)
	})

	t.Run("verify hex encoding with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey24)
		c.SetIV(ctrNonce8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ctrTestData)
		assert.Nil(t, err)

		hexResult := hex.EncodeToString(result)
		assert.Equal(t, ctrHexEncrypted24, hexResult)
	})

	t.Run("verify base64 encoding with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CTR)
		c.SetKey(ctrKey24)
		c.SetIV(ctrNonce8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ctrTestData)
		assert.Nil(t, err)

		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, ctrBase64Encrypted24, base64Result)
	})

	t.Run("verify hex to bytes conversion for 16-byte key", func(t *testing.T) {
		decodedBytes, err := hex.DecodeString(ctrHexEncrypted16)
		assert.Nil(t, err)
		assert.Equal(t, ctrRawEncrypted16, decodedBytes)
	})

	t.Run("verify base64 to bytes conversion for 16-byte key", func(t *testing.T) {
		decodedBytes, err := base64.StdEncoding.DecodeString(ctrBase64Encrypted16)
		assert.Nil(t, err)
		assert.Equal(t, ctrRawEncrypted16, decodedBytes)
	})

	t.Run("verify hex to bytes conversion for 24-byte key", func(t *testing.T) {
		decodedBytes, err := hex.DecodeString(ctrHexEncrypted24)
		assert.Nil(t, err)
		assert.Equal(t, ctrRawEncrypted24, decodedBytes)
	})

	t.Run("verify base64 to bytes conversion for 24-byte key", func(t *testing.T) {
		decodedBytes, err := base64.StdEncoding.DecodeString(ctrBase64Encrypted24)
		assert.Nil(t, err)
		assert.Equal(t, ctrRawEncrypted24, decodedBytes)
	})

	t.Run("verify all formats are consistent for 16-byte key", func(t *testing.T) {
		hexBytes, err := hex.DecodeString(ctrHexEncrypted16)
		assert.Nil(t, err)

		base64Bytes, err := base64.StdEncoding.DecodeString(ctrBase64Encrypted16)
		assert.Nil(t, err)

		assert.Equal(t, hexBytes, base64Bytes)
		assert.Equal(t, ctrRawEncrypted16, hexBytes)
		assert.Equal(t, ctrRawEncrypted16, base64Bytes)
	})

	t.Run("verify all formats are consistent for 24-byte key", func(t *testing.T) {
		hexBytes, err := hex.DecodeString(ctrHexEncrypted24)
		assert.Nil(t, err)

		base64Bytes, err := base64.StdEncoding.DecodeString(ctrBase64Encrypted24)
		assert.Nil(t, err)

		assert.Equal(t, hexBytes, base64Bytes)
		assert.Equal(t, ctrRawEncrypted24, hexBytes)
		assert.Equal(t, ctrRawEncrypted24, base64Bytes)
	})
}
