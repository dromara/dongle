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

// Test data for ECB mode
var (
	ecbKey16    = []byte("1234567890123456")         // 16-byte key for 2-key 3DES
	ecbKey24    = []byte("123456789012345678901234") // 24-byte key for 3-key 3DES
	ecbTestData = []byte("hello world")

	// Expected encrypted results for "hello world" with PKCS7 padding (verified with Python pycryptodome library)
	ecbHexEncrypted16    = "4c1a21564de3d72973cb3b918af5c91d"                                                                     // Hex encoded encrypted data (16-byte key)
	ecbBase64Encrypted16 = "TBohVk3j1ylzyzuRivXJHQ=="                                                                             // Base64 encoded encrypted data (16-byte key)
	ecbRawEncrypted16    = []byte{0x4c, 0x1a, 0x21, 0x56, 0x4d, 0xe3, 0xd7, 0x29, 0x73, 0xcb, 0x3b, 0x91, 0x8a, 0xf5, 0xc9, 0x1d} // Raw encrypted bytes (16-byte key)

	ecbHexEncrypted24    = "49d1d00a96d547393825219b9e150c2e"                                                                     // Hex encoded encrypted data (24-byte key)
	ecbBase64Encrypted24 = "SdHQCpbVRzk4JSGbnhUMLg=="                                                                             // Base64 encoded encrypted data (24-byte key)
	ecbRawEncrypted24    = []byte{0x49, 0xd1, 0xd0, 0x0a, 0x96, 0xd5, 0x47, 0x39, 0x38, 0x25, 0x21, 0x9b, 0x9e, 0x15, 0x0c, 0x2e} // Raw encrypted bytes (24-byte key)
)

func TestNewStdEncrypter_ECB(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		validKeys := [][]byte{ecbKey16, ecbKey24}
		for _, key := range validKeys {
			c := cipher.New3DesCipher(cipher.ECB)
			c.SetKey(key)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.Nil(t, encrypter.Error)
			assert.Equal(t, c, encrypter.cipher)
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
			c := cipher.New3DesCipher(cipher.ECB)
			c.SetKey(key)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.NotNil(t, encrypter.Error)
		}
	})
}

func TestStdEncrypter_Encrypt_ECB(t *testing.T) {
	t.Run("encrypt with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ecbTestData)

		assert.Nil(t, err)
		assert.Equal(t, ecbRawEncrypted16, result)

		// Verify hex encoding
		hexResult := hex.EncodeToString(result)
		assert.Equal(t, ecbHexEncrypted16, hexResult)

		// Verify base64 encoding
		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, ecbBase64Encrypted16, base64Result)
	})

	t.Run("encrypt with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey24)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ecbTestData)

		assert.Nil(t, err)
		assert.Equal(t, ecbRawEncrypted24, result)

		// Verify hex encoding
		hexResult := hex.EncodeToString(result)
		assert.Equal(t, ecbHexEncrypted24, hexResult)

		// Verify base64 encoding
		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, ecbBase64Encrypted24, base64Result)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt([]byte{})

		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("encrypt nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(nil)

		assert.Nil(t, err)
		assert.Nil(t, result)
	})
}

func TestStdDecrypter_Decrypt_ECB(t *testing.T) {
	t.Run("decrypt with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(ecbRawEncrypted16)

		assert.Nil(t, err)
		assert.Equal(t, ecbTestData, result)
	})

	t.Run("decrypt with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey24)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(ecbRawEncrypted24)

		assert.Nil(t, err)
		assert.Equal(t, ecbTestData, result)
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt([]byte{})

		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("decrypt nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(nil)

		assert.Nil(t, err)
		assert.Nil(t, result)
	})
}

func TestStreamEncrypter_Write_ECB(t *testing.T) {
	t.Run("write data to stream encrypter with 16-byte key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(ecbTestData)

		assert.Nil(t, err)
		assert.Equal(t, len(ecbTestData), n)
		assert.Equal(t, ecbRawEncrypted16, buf.Bytes())
	})

	t.Run("write data to stream encrypter with 24-byte key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey24)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(ecbTestData)

		assert.Nil(t, err)
		assert.Equal(t, len(ecbTestData), n)
		assert.Equal(t, ecbRawEncrypted24, buf.Bytes())
	})

	t.Run("write empty data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})

		assert.Nil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, []byte(nil), buf.Bytes())
	})

	t.Run("write nil data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(nil)

		assert.Nil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, []byte(nil), buf.Bytes())
	})
}

func TestStreamDecrypter_Read_ECB(t *testing.T) {
	t.Run("read data from stream decrypter with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(bytes.NewReader(ecbRawEncrypted16), c)
		buf := make([]byte, len(ecbTestData))
		n, err := decrypter.Read(buf)

		assert.Nil(t, err)
		assert.Equal(t, len(ecbTestData), n)
		assert.Equal(t, ecbTestData, buf)
	})

	t.Run("read data from stream decrypter with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey24)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(bytes.NewReader(ecbRawEncrypted24), c)
		buf := make([]byte, len(ecbTestData))
		n, err := decrypter.Read(buf)

		assert.Nil(t, err)
		assert.Equal(t, len(ecbTestData), n)
		assert.Equal(t, ecbTestData, buf)
	})

	t.Run("read empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(bytes.NewReader([]byte{}), c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)

		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(bytes.NewReader(nil), c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)

		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamEncrypter_Close_ECB(t *testing.T) {
	t.Run("close stream encrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()

		assert.Nil(t, err)
	})
}

func TestStreamEncrypter_Write_Error_ECB(t *testing.T) {
	t.Run("write error", func(t *testing.T) {
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("write error"))
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(mockWriter, c)
		n, err := encrypter.Write(ecbTestData)

		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamDecrypter_Read_Error_ECB(t *testing.T) {
	t.Run("read error", func(t *testing.T) {
		mockReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)

		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamEncrypter_Close_Error_ECB(t *testing.T) {
	t.Run("close error", func(t *testing.T) {
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("close error"))
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(mockWriter, c)
		err := encrypter.Close()

		assert.NotNil(t, err)
	})
}

func TestECB_EncodingFormats(t *testing.T) {
	t.Run("verify hex encoding with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ecbTestData)
		assert.Nil(t, err)

		hexResult := hex.EncodeToString(result)
		assert.Equal(t, ecbHexEncrypted16, hexResult)
	})

	t.Run("verify base64 encoding with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey16)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ecbTestData)
		assert.Nil(t, err)

		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, ecbBase64Encrypted16, base64Result)
	})

	t.Run("verify hex encoding with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey24)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ecbTestData)
		assert.Nil(t, err)

		hexResult := hex.EncodeToString(result)
		assert.Equal(t, ecbHexEncrypted24, hexResult)
	})

	t.Run("verify base64 encoding with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.ECB)
		c.SetKey(ecbKey24)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(ecbTestData)
		assert.Nil(t, err)

		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, ecbBase64Encrypted24, base64Result)
	})

	t.Run("verify hex to bytes conversion for 16-byte key", func(t *testing.T) {
		decodedBytes, err := hex.DecodeString(ecbHexEncrypted16)
		assert.Nil(t, err)
		assert.Equal(t, ecbRawEncrypted16, decodedBytes)
	})

	t.Run("verify base64 to bytes conversion for 16-byte key", func(t *testing.T) {
		decodedBytes, err := base64.StdEncoding.DecodeString(ecbBase64Encrypted16)
		assert.Nil(t, err)
		assert.Equal(t, ecbRawEncrypted16, decodedBytes)
	})

	t.Run("verify hex to bytes conversion for 24-byte key", func(t *testing.T) {
		decodedBytes, err := hex.DecodeString(ecbHexEncrypted24)
		assert.Nil(t, err)
		assert.Equal(t, ecbRawEncrypted24, decodedBytes)
	})

	t.Run("verify base64 to bytes conversion for 24-byte key", func(t *testing.T) {
		decodedBytes, err := base64.StdEncoding.DecodeString(ecbBase64Encrypted24)
		assert.Nil(t, err)
		assert.Equal(t, ecbRawEncrypted24, decodedBytes)
	})

	t.Run("verify all formats are consistent for 16-byte key", func(t *testing.T) {
		hexBytes, err := hex.DecodeString(ecbHexEncrypted16)
		assert.Nil(t, err)

		base64Bytes, err := base64.StdEncoding.DecodeString(ecbBase64Encrypted16)
		assert.Nil(t, err)

		assert.Equal(t, hexBytes, base64Bytes)
		assert.Equal(t, ecbRawEncrypted16, hexBytes)
		assert.Equal(t, ecbRawEncrypted16, base64Bytes)
	})

	t.Run("verify all formats are consistent for 24-byte key", func(t *testing.T) {
		hexBytes, err := hex.DecodeString(ecbHexEncrypted24)
		assert.Nil(t, err)

		base64Bytes, err := base64.StdEncoding.DecodeString(ecbBase64Encrypted24)
		assert.Nil(t, err)

		assert.Equal(t, hexBytes, base64Bytes)
		assert.Equal(t, ecbRawEncrypted24, hexBytes)
		assert.Equal(t, ecbRawEncrypted24, base64Bytes)
	})
}
