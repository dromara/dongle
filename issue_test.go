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

// https://github.com/golang-package/dongle/issues/34
func TestIssue34(t *testing.T) {
	kp := keypair.NewSm2KeyPair()
	kp.SetOrder(keypair.C1C3C2)
	kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgXuXGh4oAu+dLjqiT
/HbjYbZpThuzFbTrWlin3J0fGnGgCgYIKoEcz1UBgi2hRANCAAR08hilFva9Maqq
1Tk8nJR4EFNhHFBB4Vr5duPaxXqAypfNj/dguqBRrcQO6LYu/ucVFf4pS4/+z9WL
luEJL+Cf
-----END PRIVATE KEY-----`)
	ciphertext := []byte{
		0x04,
		0xf9, 0x72, 0x8a, 0xc8, 0x32, 0xca, 0x24, 0xd4,
		0xc3, 0x83, 0xc1, 0x29, 0x89, 0x8f, 0xd9, 0x0b,
		0xd5, 0x9a, 0x03, 0xdc, 0xec, 0x23, 0x02, 0x7c,
		0x44, 0x08, 0x27, 0x76, 0x9f, 0x2d, 0x2c, 0xd0,
		0x02, 0x8c, 0x97, 0xfd, 0x5b, 0xfa, 0x45, 0x18,
		0x2c, 0xb2, 0x91, 0xd1, 0x5d, 0xae, 0x5c, 0x0b,
		0xd6, 0x3a, 0xf5, 0xde, 0x68, 0x09, 0x87, 0x4d,
		0x7d, 0xc4, 0x5b, 0x42, 0xc8, 0x4d, 0x1c, 0xc0,
		0x68, 0x00, 0x21, 0x59, 0x35, 0x9b, 0x0c, 0x81,
		0xac, 0x1a, 0x19, 0x30, 0x0d, 0x16, 0x4e, 0x62,
		0x5c, 0x5e, 0xb2, 0x37, 0x32, 0xb6, 0x02, 0x95,
		0x83, 0x30, 0x8c, 0x3b, 0x01, 0x0d, 0x66, 0xec,
		0xf9, 0xd2, 0xc8, 0xb2, 0x06, 0xe3, 0x5b, 0xe9,
		0xb9, 0xd5, 0xe4, 0x19, 0xb1, 0xb5, 0x83, 0x8c,
	}

	decrypter := Decrypt.FromRawBytes(ciphertext).BySm2(kp)
	assert.Nil(t, decrypter.Error)

	expectedHex := "c6f2cc55b8cb73f3a75bf88b5416e6a0"
	actualHex := fmt.Sprintf("%x", decrypter.ToString())

	assert.Equal(t, expectedHex, actualHex)
}

// https://github.com/dromara/dongle/issues/39
func TestIssue39(t *testing.T) {
	// Issue: JSEncrypt encrypts data with PKCS1v15 padding, PHP can decrypt it,
	// but dongle fails with "crypto/rsa: decryption error" when using PKCS8 private key format
	// without explicitly setting padding to PKCS1v15.
	//
	// Root cause: When Format is PKCS8 and Padding is not set, dongle defaults to OAEP padding,
	// which is incompatible with JSEncrypt's PKCS1v15 padding.

	// Use the actual keys from the issue report
	privateKeyPKCS8 := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDLxGpZFgwr66Si
bZS3k4dgFF3A4TKgyDJ2EtMyrrk/I1bhtIE2m/AGHOzVroFcM3c/VRd+LDTMGugR
x8KkUMjjqaMaq1a7U4jgpeBy0eYAii4mAyx3qxQbhx2slE6OyIDgu6IvfaIX3l2w
zO9gt+hkEqosKiNVdWabI8e86Nit40MkR+ubWG7LY+oRkipuXOBV3PKHGn4ZbL0J
V4uffZhKoIwSA/c3ZLp3Acsr5OAZGWJ86OkHx5+SRV0dmXQdNCh0r+TKZ2I7qRIy
SkYsWRJ5Muud7nzbl7ccwt1eK8lWt86idwOKw5ag+CnizR/y6rd1AxDkGkSB7K50
A4xpG14vAgMBAAECggEAQY/ggepwnx8SGTr12z0qFRVodvteXVIcvlXfQ1LpgrGd
rkB0RLxWtbjP0Q71S1O53hREW1Hg6P0NR09FRrZBdNLrilSvstU1WMa2WWtEvE65
e3yQ7a4LabIHL7SGNDW6FdT5YZtkMJbZAV5m9PEnYi+JNm2WcdQ039za0uL+eK/w
ItKuMoaH7rwRRA1TCZm1PL00hCRpOk6fhDaOtfrEg0lIKNDKjkroZcA3hemOURn6
Z9d6dIca7+QApvB47AyZKJeAKKwqNeWH5v0VTkqeI2nJyh2bD/QAHWjp4qxsLEJ/
98RU3pX/skjLGQVs+Mda0jSLfiUQvRp8ystoEcsTuQKBgQDcG+fdVQHzXVA3XbUB
eLwkzx0mrLfRrQ/nfkZmHPU6xBQ3YAIlAVoS/B5Iq0emqpS1S4yzYQ+fIoDYqkrE
Xr+K9SXsTeJOqd7EIkrlZ+LvmrZUK8ul+f0k1vIgyS0eIAm6HfHDg3/LIVGG1Gm+
Ek7V2ByF2IMXOozogHjDmPPyNwKBgQDs/llzezTwREJUYDJfc/C9fNlvEkZk1ZkY
c4s+gCdFo3ghN/QZD9YEVBMBi3Xw6i7+vhZ9RI5nHugjEopN0AdS/vOET+lsxuPF
ojxbIsHmT+K4h6BBHBJP3xtOTx9mwFOYLxJ/Kne8BzrQE0fRRp2ANxq242YYKI2D
g+h5XQrXyQKBgH18P1U06JbJRTk7aD09iu3lUjZBU87rPlz45cPDkJ9/OBNV3gMg
4SxfphhB5eiD6aHuP3noxRIxhol/lH6dkc/z8TnmMTYtrD3fWxmsf3mgl4AnM8Qd
YI/HJ2U/rEQ3ebQs7C9N4eZ5yVP3940QPPe3bJN2G0575+eJjs/cfH9DAoGAAwbY
k53+NhdZFYTI/+kWKQVgLYf5OC52LxbCr4Cpf70vupThXDSUkieUuo9SaUpEYWKC
HQV0ICMH6fLBq269uTSiXY07uPTtUcfZp3xRJ6Tbi2nIBSzbmwOJcL2X9BL+vlHT
laYwM0mQWbn1T9nsBwgtIirTUfmqnQRhQrOKgOkCgYBT8Fon+y/MoOMTZeSrFMv7
jmZYbLhw73/v6cy1gH0HTFlNYPeL2vQt5AKBdNr0HE2ROMz1r2oBhChxRNpuK8iZ
f+6jpQu+12uBTMJAsc0y/8Wv49YSfggLmHvsrmHR9KeoDMbvcy8MScDpLk9xftgw
FqpWB6rp2FLmGRLDf33Wow==
-----END PRIVATE KEY-----`)

	publicKeyPKCS8 := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8RqWRYMK+ukom2Ut5OH
YBRdwOEyoMgydhLTMq65PyNW4bSBNpvwBhzs1a6BXDN3P1UXfiw0zBroEcfCpFDI
46mjGqtWu1OI4KXgctHmAIouJgMsd6sUG4cdrJROjsiA4LuiL32iF95dsMzvYLfo
ZBKqLCojVXVmmyPHvOjYreNDJEfrm1huy2PqEZIqblzgVdzyhxp+GWy9CVeLn32Y
SqCMEgP3N2S6dwHLK+TgGRlifOjpB8efkkVdHZl0HTQodK/kymdiO6kSMkpGLFkS
eTLrne5825e3HMLdXivJVrfOoncDisOWoPgp4s0f8uq3dQMQ5BpEgeyudAOMaRte
LwIDAQAB
-----END PUBLIC KEY-----`)

	// Actual ciphertext from the issue (JSEncrypt encrypted "123456" with PKCS1v15)
	ciphertextFromJSEncrypt := "v0ukJgNwFliJBlZEJQADxfYFOiVSxSqAbkvBn25OIVqxEdlRbAGDF4K72pOILSCY0j8UDatJy/xfxE24+oJVP1PmO1fBfdhzdTzn1F1R00CPIPSw+9TdZY8ntYKFojhvbKcURXYfnVuh3LcMjYTynIcosPDl1b6it2ZWUK+HmxVfFFL+FCJDYfFUDgcDkwgRmI2ydDuyqM4aDaIsVk43hzsXoyj/yVH9gM2eRo74/M6jQmEQ3sLZf7GmoDsuAkh/6SDs1JV1eh1ZmX2aXDr04F/NLouO3bIQ+6WvL4OIpWZamC4/lFRme3Mmuonff67bd+1LkhPe9S9d6yxf/Wl4lA=="
	expectedPlaintext := "123456"

	// Reproduce the issue with actual data from GitHub issue #39
	t.Run("reproduce_issue_with_actual_data", func(t *testing.T) {
		// Try to decrypt with user's incorrect configuration (reproducing the issue)
		kpDecryptWrong := keypair.NewRsaKeyPair()
		kpDecryptWrong.SetFormat(keypair.PKCS8)
		kpDecryptWrong.SetHash(crypto.SHA256)
		// Not setting padding - this causes PKCS8 to default to OAEP
		kpDecryptWrong.PrivateKey = privateKeyPKCS8

		decrypterWrong := Decrypt.FromBase64String(ciphertextFromJSEncrypt).ByRsa(kpDecryptWrong)
		// This should fail with "crypto/rsa: decryption error"
		assert.Error(t, decrypterWrong.Error, "Should fail: OAEP cannot decrypt PKCS1v15 encrypted data")
		assert.Contains(t, decrypterWrong.Error.Error(), "decryption error", "Error should contain 'decryption error'")
	})

	// Show the correct solution: Explicitly set PKCS1v15 padding
	t.Run("correct_solution_with_actual_data", func(t *testing.T) {
		// Correct configuration: Explicitly set PKCS1v15 padding
		kpDecryptCorrect := keypair.NewRsaKeyPair()
		kpDecryptCorrect.SetFormat(keypair.PKCS8)
		kpDecryptCorrect.SetHash(crypto.SHA256)
		kpDecryptCorrect.SetPadding(keypair.PKCS1v15) // Must explicitly set PKCS1v15
		kpDecryptCorrect.PrivateKey = privateKeyPKCS8

		decrypted := Decrypt.FromBase64String(ciphertextFromJSEncrypt).ByRsa(kpDecryptCorrect).ToString()
		assert.Equal(t, expectedPlaintext, decrypted, "Should successfully decrypt JSEncrypt data with PKCS1v15 padding")
	})

	// Additional test: Encrypt and decrypt with the same configuration
	t.Run("encrypt_and_decrypt_with_pkcs1v15", func(t *testing.T) {
		// Encrypt with PKCS1v15 (simulating JSEncrypt)
		kpEncrypt := keypair.NewRsaKeyPair()
		kpEncrypt.SetFormat(keypair.PKCS8)
		kpEncrypt.SetHash(crypto.SHA256)
		kpEncrypt.SetPadding(keypair.PKCS1v15) // JSEncrypt uses PKCS1v15
		kpEncrypt.PublicKey = publicKeyPKCS8

		plaintext := "test password"
		ciphertext := Encrypt.FromString(plaintext).ByRsa(kpEncrypt).ToBase64String()
		assert.NotEmpty(t, ciphertext)

		// Decrypt with PKCS1v15
		kpDecrypt := keypair.NewRsaKeyPair()
		kpDecrypt.SetFormat(keypair.PKCS8)
		kpDecrypt.SetHash(crypto.SHA256)
		kpDecrypt.SetPadding(keypair.PKCS1v15)
		kpDecrypt.PrivateKey = privateKeyPKCS8

		decrypted := Decrypt.FromBase64String(ciphertext).ByRsa(kpDecrypt).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	// Additional test: PKCS1 format keys default to PKCS1v15 padding
	t.Run("pkcs1_format_works_by_default", func(t *testing.T) {
		// Generate PKCS1 format key pair
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		err := kp.GenKeyPair(2048)
		assert.NoError(t, err)

		plaintext := "test message"

		// PKCS1 format defaults to PKCS1v15 padding, so no need to set it explicitly
		ciphertext := Encrypt.FromString(plaintext).ByRsa(kp).ToBase64String()
		assert.NotEmpty(t, ciphertext)

		decrypted := Decrypt.FromBase64String(ciphertext).ByRsa(kp).ToString()
		assert.Equal(t, plaintext, decrypted)
	})

	// Test cross-format compatibility with explicit padding
	t.Run("cross_format_with_explicit_padding", func(t *testing.T) {
		// Generate PKCS1 format key pair for encryption
		kp1 := keypair.NewRsaKeyPair()
		kp1.SetFormat(keypair.PKCS1)
		kp1.SetHash(crypto.SHA256)
		err := kp1.GenKeyPair(2048)
		assert.NoError(t, err)

		plaintext := "cross format test"

		// Encrypt with PKCS1 format (defaults to PKCS1v15)
		ciphertext := Encrypt.FromString(plaintext).ByRsa(kp1).ToBase64String()
		assert.NotEmpty(t, ciphertext)

		// Decrypt with PKCS8 format key but explicit PKCS1v15 padding
		kp2 := keypair.NewRsaKeyPair()
		kp2.SetFormat(keypair.PKCS8)
		kp2.SetHash(crypto.SHA256)
		kp2.SetPadding(keypair.PKCS1v15) // Explicitly set PKCS1v15 for compatibility
		kp2.PrivateKey = kp1.PrivateKey

		decrypted := Decrypt.FromBase64String(ciphertext).ByRsa(kp2).ToString()
		assert.Equal(t, plaintext, decrypted)
	})
}
