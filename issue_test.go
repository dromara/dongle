package dongle

import (
	"crypto"
	"crypto/md5"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/hash"
	"github.com/stretchr/testify/assert"
)

// https://github.com/dromara/dongle/issues/28
func TestIssue28(t *testing.T) {
	var str = "1234567"

	h := md5.New()
	_, _ = io.WriteString(h, str)
	md5Std := fmt.Sprintf("%x", h.Sum(nil))

	md5ByDongle1 := Hash.FromString(str).ByMd5().ToHexString()
	md5ByDongle2 := hash.NewHasher().FromString(str).ByMd5().ToHexString()
	md5ByDongle3 := Hash.FromString(str).WithKey([]byte("123456")).ByMd5().ToHexString()
	md5ByDongle4 := Hash.FromString(str).ByMd5().ToHexString()

	assert.Equalf(t, md5Std, md5ByDongle1, "1.默认全局无指定Key MD5结果应与原生结果一致")
	assert.Equalf(t, md5Std, md5ByDongle2, "2.新建实例无指定Key MD5结果应与原生结果一致")
	assert.NotEqualf(t, md5Std, md5ByDongle3, "3.默认全局指定Key MD5结果应与原生结果不一致")
	assert.Equalf(t, md5Std, md5ByDongle4, "4.默认全局无指定Key MD5结果应与原生结果一致")
}

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

// https://github.com/dromara/dongle/issues/30
func TestIssue30(t *testing.T) {
	// Test 1: Invalid public key test
	t.Run("invalid_public_key_test", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetHash(crypto.SHA256)
		kp.SetFormat(keypair.PKCS8)
		kp.GenKeyPair(2048)

		kp2 := keypair.NewRsaKeyPair()
		kp2.SetHash(crypto.SHA256)
		kp2.SetFormat(keypair.PKCS8)
		kp2.PublicKey = []byte("123") // Invalid public key

		// Test 1: kp signs, kp verifies - should be true
		base64Bytes1 := Sign.FromString("hello world").ByRsa(kp).ToBase64Bytes()
		result1 := Verify.FromString("hello world").WithBase64Sign(base64Bytes1).ByRsa(kp).ToBool()
		assert.True(t, result1, "test1: kp signs, kp verifies should be true")

		// Test 2: kp2 signs, kp2 verifies - should be false (invalid public key)
		base64Bytes2 := Sign.FromString("hello world").ByRsa(kp2).ToBase64Bytes()
		result2 := Verify.FromString("hello world").WithBase64Sign(base64Bytes2).ByRsa(kp2).ToBool()
		assert.False(t, result2, "test2: kp2 signs, kp2 verifies should be false (invalid public key)")

		// Test 3: kp signs, kp2 verifies - should be false (kp2 has invalid public key)
		base64Bytes3 := Sign.FromString("hello world").ByRsa(kp).ToBase64Bytes()
		result3 := Verify.FromString("hello world").WithBase64Sign(base64Bytes3).ByRsa(kp2).ToBool()
		assert.False(t, result3, "test3: kp signs, kp2 verifies should be false (kp2 has invalid public key)")

		// Test 4: kp2 signs, kp verifies - should be false (kp2 cannot sign with invalid key)
		base64Bytes4 := Sign.FromString("hello world").ByRsa(kp2).ToBase64Bytes()
		result4 := Verify.FromString("hello world").WithBase64Sign(base64Bytes4).ByRsa(kp).ToBool()
		assert.False(t, result4, "test4: kp2 signs, kp verifies should be false (kp2 cannot sign with invalid key)")
	})

	// Test 2: Same public key test
	t.Run("same_public_key_test", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetHash(crypto.SHA256)
		kp.SetFormat(keypair.PKCS8)
		kp.GenKeyPair(2048)

		kp2 := keypair.NewRsaKeyPair()
		kp2.SetHash(crypto.SHA256)
		kp2.SetFormat(keypair.PKCS8)
		kp2.PublicKey = kp.PublicKey // Same public key

		// Test 1: kp signs, kp verifies - should be true
		base64Bytes1 := Sign.FromString("hello world").ByRsa(kp).ToBase64Bytes()
		result1 := Verify.FromString("hello world").WithBase64Sign(base64Bytes1).ByRsa(kp).ToBool()
		assert.True(t, result1, "test1: kp signs, kp verifies should be true")

		// Test 2: kp2 signs, kp2 verifies - should be false (kp2 has no private key)
		base64Bytes2 := Sign.FromString("hello world").ByRsa(kp2).ToBase64Bytes()
		result2 := Verify.FromString("hello world").WithBase64Sign(base64Bytes2).ByRsa(kp2).ToBool()
		assert.False(t, result2, "test2: kp2 signs, kp2 verifies should be false (kp2 has no private key)")

		// Test 3: kp signs, kp2 verifies - should be true (kp2 has same public key)
		base64Bytes3 := Sign.FromString("hello world").ByRsa(kp).ToBase64Bytes()
		result3 := Verify.FromString("hello world").WithBase64Sign(base64Bytes3).ByRsa(kp2).ToBool()
		assert.True(t, result3, "test3: kp signs, kp2 verifies should be true (kp2 has same public key)")

		// Test 4: kp2 signs, kp verifies - should be false (kp2 cannot sign without private key)
		base64Bytes4 := Sign.FromString("hello world").ByRsa(kp2).ToBase64Bytes()
		result4 := Verify.FromString("hello world").WithBase64Sign(base64Bytes4).ByRsa(kp).ToBool()
		assert.False(t, result4, "test4: kp2 signs, kp verifies should be false (kp2 cannot sign without private key)")
	})

	// Test 3: Cross-verification test with different key pairs
	t.Run("cross_verification_test", func(t *testing.T) {
		kp1 := keypair.NewRsaKeyPair()
		kp1.SetHash(crypto.SHA256)
		kp1.SetFormat(keypair.PKCS8)
		kp1.GenKeyPair(2048)

		kp2 := keypair.NewRsaKeyPair()
		kp2.SetHash(crypto.SHA256)
		kp2.SetFormat(keypair.PKCS8)
		kp2.GenKeyPair(2048)

		// Test: kp1 signs, kp2 verifies - should be false (different key pairs)
		base64Bytes := Sign.FromString("hello world").ByRsa(kp1).ToBase64Bytes()
		result := Verify.FromString("hello world").WithBase64Sign(base64Bytes).ByRsa(kp2).ToBool()
		assert.False(t, result, "Cross-verification with different key pairs should be false")

		// Test: kp1 signs, kp1 verifies - should be true (same key pair)
		result2 := Verify.FromString("hello world").WithBase64Sign(base64Bytes).ByRsa(kp1).ToBool()
		assert.True(t, result2, "Verification with same key pair should be true")
	})

	// Test 4: Empty signature test
	t.Run("empty_signature_test", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetHash(crypto.SHA256)
		kp.SetFormat(keypair.PKCS8)
		kp.GenKeyPair(2048)

		// Test with empty signature
		result := Verify.FromString("hello world").WithBase64Sign([]byte{}).ByRsa(kp).ToBool()
		assert.False(t, result, "Verification with empty signature should be false")
	})

	// Test 5: Invalid signature test
	t.Run("invalid_signature_test", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetHash(crypto.SHA256)
		kp.SetFormat(keypair.PKCS8)
		kp.GenKeyPair(2048)

		// Test with invalid signature
		invalidSignature := []byte("invalid_signature_data")
		result := Verify.FromString("hello world").WithRawSign(invalidSignature).ByRsa(kp).ToBool()
		assert.False(t, result, "Verification with invalid signature should be false")
	})
}
