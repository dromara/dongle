package dongle

import (
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

// https://github.com/dromara/dongle/issues/29
func TestIssue29(t *testing.T) {
	key := []byte("dongle1234567890")
	iv := []byte("1234567890123456")
	c := cipher.NewAesCipher(cipher.CFB)
	c.SetKey(key)
	c.SetIV(iv)
	c.SetPadding(cipher.PKCS7)

	t.Run("test_48_chars", func(t *testing.T) {
		text := strings.Repeat("1", 48)

		// Test dongle library
		ciphertext := Encrypt.FromString(text).ByAes(c).ToBase64String()
		plaintext := Decrypt.FromBase64String(ciphertext).ByAes(c).ToString()
		dongleSuccess := plaintext == text

		assert.True(t, dongleSuccess, "Dongle library should decrypt 48 chars correctly")
	})

	t.Run("test_49_chars", func(t *testing.T) {
		text := strings.Repeat("1", 49)

		ciphertext := Encrypt.FromString(text).ByAes(c).ToBase64String()
		plaintext := Decrypt.FromBase64String(ciphertext).ByAes(c).ToString()
		dongleSuccess := plaintext == text

		assert.True(t, dongleSuccess, "Dongle library should decrypt 49 chars correctly")
	})

	t.Run("test_different_chars_48", func(t *testing.T) {
		testCases := []string{
			strings.Repeat("0", 48),
			strings.Repeat("2", 48),
			strings.Repeat("a", 48),
			strings.Repeat("A", 48),
		}

		for _, text := range testCases {
			t.Run("char_"+string(text[0]), func(t *testing.T) {
				// Test dongle library
				ciphertext := Encrypt.FromString(text).ByAes(c).ToBase64String()
				plaintext := Decrypt.FromBase64String(ciphertext).ByAes(c).ToString()
				dongleSuccess := plaintext == text

				assert.True(t, dongleSuccess, "Dongle library should decrypt 48 chars of '%c' correctly", text[0])
			})
		}
	})

	t.Run("test_different_chars_49", func(t *testing.T) {
		testCases := []string{
			strings.Repeat("0", 49),
			strings.Repeat("2", 49),
			strings.Repeat("a", 49),
			strings.Repeat("A", 49),
		}

		for _, text := range testCases {
			t.Run("char_"+string(text[0]), func(t *testing.T) {
				// Test dongle library
				ciphertext := Encrypt.FromString(text).ByAes(c).ToBase64String()
				plaintext := Decrypt.FromBase64String(ciphertext).ByAes(c).ToString()
				dongleSuccess := plaintext == text

				assert.True(t, dongleSuccess, "Dongle library should decrypt 49 chars of '%c' correctly", text[0])
			})
		}
	})

	t.Run("test_various_lengths", func(t *testing.T) {
		lengths := []int{47, 48, 49, 50, 64, 80, 100}

		for _, length := range lengths {
			t.Run("length_"+string(rune(length)), func(t *testing.T) {
				text := strings.Repeat("1", length)

				// Test dongle library
				ciphertext := Encrypt.FromString(text).ByAes(c).ToBase64String()
				plaintext := Decrypt.FromBase64String(ciphertext).ByAes(c).ToString()
				dongleSuccess := plaintext == text

				assert.True(t, dongleSuccess, "Dongle library should decrypt %d chars correctly", length)
			})
		}
	})

	t.Run("test_ofb_mode", func(t *testing.T) {
		// Test OFB mode as mentioned in the issue
		ofbCipher := cipher.NewAesCipher(cipher.OFB)
		ofbCipher.SetKey(key)
		ofbCipher.SetIV(iv)
		ofbCipher.SetPadding(cipher.PKCS7)

		lengths := []int{47, 48, 49, 50, 64, 80}

		for _, length := range lengths {
			t.Run("ofb_length_"+string(rune(length)), func(t *testing.T) {
				text := strings.Repeat("1", length)

				ciphertext := Encrypt.FromString(text).ByAes(ofbCipher).ToBase64String()
				plaintext := Decrypt.FromBase64String(ciphertext).ByAes(ofbCipher).ToString()
				dongleSuccess := plaintext == text

				assert.True(t, dongleSuccess, "Dongle library should decrypt %d chars with OFB mode correctly", length)
			})
		}
	})
}
