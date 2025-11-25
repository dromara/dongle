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

// Test data for CFB mode
var (
	cfbKey16    = []byte("1234567890123456")         // 16-byte key for 2-key 3DES
	cfbKey24    = []byte("123456789012345678901234") // 24-byte key for 3-key 3DES
	cfbIV8      = []byte("87654321")                 // 8-byte IV for CFB
	cfbTestData = []byte("hello world")

	// Expected encrypted results for "hello world" (verified with Python cryptography library)
	cfbHexEncrypted16    = "68a728fc8bfdd4f0c18719"                                                 // Hex encoded encrypted data (16-byte key)
	cfbBase64Encrypted16 = "aKco/Iv91PDBhxk="                                                       // Base64 encoded encrypted data (16-byte key)
	cfbRawEncrypted16    = []byte{0x68, 0xa7, 0x28, 0xfc, 0x8b, 0xfd, 0xd4, 0xf0, 0xc1, 0x87, 0x19} // Raw encrypted bytes (16-byte key)

	cfbHexEncrypted24    = "047384de28c83ff6ec2b38"                                                 // Hex encoded encrypted data (24-byte key)
	cfbBase64Encrypted24 = "BHOE3ijIP/bsKzg="                                                       // Base64 encoded encrypted data (24-byte key)
	cfbRawEncrypted24    = []byte{0x04, 0x73, 0x84, 0xde, 0x28, 0xc8, 0x3f, 0xf6, 0xec, 0x2b, 0x38} // Raw encrypted bytes (24-byte key)
)

func TestNewStdEncrypter_CFB(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		validKeys := [][]byte{cfbKey16, cfbKey24}
		for _, key := range validKeys {
			c := cipher.New3DesCipher(cipher.CFB)
			c.SetKey(key)
			c.SetIV(cfbIV8)

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
			c := cipher.New3DesCipher(cipher.CFB)
			c.SetKey(key)
			c.SetIV(cfbIV8)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.NotNil(t, encrypter.Error)
		}
	})
}

func TestStdEncrypter_Encrypt_CFB(t *testing.T) {
	t.Run("encrypt with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(cfbTestData)

		assert.Nil(t, err)
		assert.Equal(t, cfbRawEncrypted16, result)

		// Verify hex encoding
		hexResult := hex.EncodeToString(result)
		assert.Equal(t, cfbHexEncrypted16, hexResult)

		// Verify base64 encoding
		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, cfbBase64Encrypted16, base64Result)
	})

	t.Run("encrypt with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey24)
		c.SetIV(cfbIV8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(cfbTestData)

		assert.Nil(t, err)
		assert.Equal(t, cfbRawEncrypted24, result)

		// Verify hex encoding
		hexResult := hex.EncodeToString(result)
		assert.Equal(t, cfbHexEncrypted24, hexResult)

		// Verify base64 encoding
		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, cfbBase64Encrypted24, base64Result)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt([]byte{})

		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("encrypt nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(nil)

		assert.Nil(t, err)
		assert.Nil(t, result)
	})
}

func TestStdDecrypter_Decrypt_CFB(t *testing.T) {
	t.Run("decrypt with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(cfbRawEncrypted16)

		assert.Nil(t, err)
		assert.Equal(t, cfbTestData, result)
	})

	t.Run("decrypt with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey24)
		c.SetIV(cfbIV8)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(cfbRawEncrypted24)

		assert.Nil(t, err)
		assert.Equal(t, cfbTestData, result)
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt([]byte{})

		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("decrypt nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(nil)

		assert.Nil(t, err)
		assert.Nil(t, result)
	})
}

func TestStreamEncrypter_Write_CFB(t *testing.T) {
	t.Run("write data to stream encrypter with 16-byte key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(cfbTestData)

		assert.Nil(t, err)
		assert.Equal(t, len(cfbTestData), n)
		assert.Equal(t, cfbRawEncrypted16, buf.Bytes())
	})

	t.Run("write data to stream encrypter with 24-byte key", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey24)
		c.SetIV(cfbIV8)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(cfbTestData)

		assert.Nil(t, err)
		assert.Equal(t, len(cfbTestData), n)
		assert.Equal(t, cfbRawEncrypted24, buf.Bytes())
	})

	t.Run("write empty data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})

		assert.Nil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, []byte(nil), buf.Bytes())
	})

	t.Run("write nil data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(nil)

		assert.Nil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, []byte(nil), buf.Bytes())
	})
}

func TestStreamDecrypter_Read_CFB(t *testing.T) {
	t.Run("read data from stream decrypter with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		decrypter := NewStreamDecrypter(bytes.NewReader(cfbRawEncrypted16), c)
		buf := make([]byte, len(cfbTestData))
		n, err := decrypter.Read(buf)

		assert.Nil(t, err)
		assert.Equal(t, len(cfbTestData), n)
		assert.Equal(t, cfbTestData, buf)
	})

	t.Run("read data from stream decrypter with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey24)
		c.SetIV(cfbIV8)

		decrypter := NewStreamDecrypter(bytes.NewReader(cfbRawEncrypted24), c)
		buf := make([]byte, len(cfbTestData))
		n, err := decrypter.Read(buf)

		assert.Nil(t, err)
		assert.Equal(t, len(cfbTestData), n)
		assert.Equal(t, cfbTestData, buf)
	})

	t.Run("read empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		decrypter := NewStreamDecrypter(bytes.NewReader([]byte{}), c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)

		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		decrypter := NewStreamDecrypter(bytes.NewReader(nil), c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)

		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamEncrypter_Close_CFB(t *testing.T) {
	t.Run("close stream encrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()

		assert.Nil(t, err)
	})
}

func TestStreamEncrypter_Write_Error_CFB(t *testing.T) {
	t.Run("write error", func(t *testing.T) {
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("write error"))
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStreamEncrypter(mockWriter, c)
		n, err := encrypter.Write(cfbTestData)

		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamDecrypter_Read_Error_CFB(t *testing.T) {
	t.Run("read error", func(t *testing.T) {
		mockReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)

		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamEncrypter_Close_Error_CFB(t *testing.T) {
	t.Run("close error", func(t *testing.T) {
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("close error"))
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStreamEncrypter(mockWriter, c)
		err := encrypter.Close()

		assert.NotNil(t, err)
	})
}

func TestCFB_EncodingFormats(t *testing.T) {
	t.Run("verify hex encoding with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(cfbTestData)
		assert.Nil(t, err)

		hexResult := hex.EncodeToString(result)
		assert.Equal(t, cfbHexEncrypted16, hexResult)
	})

	t.Run("verify base64 encoding with 16-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey16)
		c.SetIV(cfbIV8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(cfbTestData)
		assert.Nil(t, err)

		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, cfbBase64Encrypted16, base64Result)
	})

	t.Run("verify hex encoding with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey24)
		c.SetIV(cfbIV8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(cfbTestData)
		assert.Nil(t, err)

		hexResult := hex.EncodeToString(result)
		assert.Equal(t, cfbHexEncrypted24, hexResult)
	})

	t.Run("verify base64 encoding with 24-byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CFB)
		c.SetKey(cfbKey24)
		c.SetIV(cfbIV8)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(cfbTestData)
		assert.Nil(t, err)

		base64Result := base64.StdEncoding.EncodeToString(result)
		assert.Equal(t, cfbBase64Encrypted24, base64Result)
	})

	t.Run("verify hex to bytes conversion for 16-byte key", func(t *testing.T) {
		decodedBytes, err := hex.DecodeString(cfbHexEncrypted16)
		assert.Nil(t, err)
		assert.Equal(t, cfbRawEncrypted16, decodedBytes)
	})

	t.Run("verify base64 to bytes conversion for 16-byte key", func(t *testing.T) {
		decodedBytes, err := base64.StdEncoding.DecodeString(cfbBase64Encrypted16)
		assert.Nil(t, err)
		assert.Equal(t, cfbRawEncrypted16, decodedBytes)
	})

	t.Run("verify hex to bytes conversion for 24-byte key", func(t *testing.T) {
		decodedBytes, err := hex.DecodeString(cfbHexEncrypted24)
		assert.Nil(t, err)
		assert.Equal(t, cfbRawEncrypted24, decodedBytes)
	})

	t.Run("verify base64 to bytes conversion for 24-byte key", func(t *testing.T) {
		decodedBytes, err := base64.StdEncoding.DecodeString(cfbBase64Encrypted24)
		assert.Nil(t, err)
		assert.Equal(t, cfbRawEncrypted24, decodedBytes)
	})

	t.Run("verify all formats are consistent for 16-byte key", func(t *testing.T) {
		hexBytes, err := hex.DecodeString(cfbHexEncrypted16)
		assert.Nil(t, err)

		base64Bytes, err := base64.StdEncoding.DecodeString(cfbBase64Encrypted16)
		assert.Nil(t, err)

		assert.Equal(t, hexBytes, base64Bytes)
		assert.Equal(t, cfbRawEncrypted16, hexBytes)
		assert.Equal(t, cfbRawEncrypted16, base64Bytes)
	})

	t.Run("verify all formats are consistent for 24-byte key", func(t *testing.T) {
		hexBytes, err := hex.DecodeString(cfbHexEncrypted24)
		assert.Nil(t, err)

		base64Bytes, err := base64.StdEncoding.DecodeString(cfbBase64Encrypted24)
		assert.Nil(t, err)

		assert.Equal(t, hexBytes, base64Bytes)
		assert.Equal(t, cfbRawEncrypted24, hexBytes)
		assert.Equal(t, cfbRawEncrypted24, base64Bytes)
	})
}
