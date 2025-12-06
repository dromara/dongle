package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"

	"github.com/dromara/dongle/hash/sm3"
	"github.com/dromara/dongle/internal/utils"
)

// generateTestKeyPair creates a test key pair
func generateTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	curve := NewCurve()
	d, err := RandScalar(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate random scalar: %v", err)
	}
	x, y := curve.ScalarBaseMult(d.Bytes())
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}
	return priv, &priv.PublicKey
}

// generateTestPublicKey creates a test public key (when private key is not needed)
func generateTestPublicKey(t *testing.T) *ecdsa.PublicKey {
	_, pub := generateTestKeyPair(t)
	return pub
}

// generateTestDigest generates a test digest for Sign/Verify
func generateTestDigest(message []byte) []byte {
	h := sm3.New()
	h.Write(message)
	return h.Sum(nil)
}

// marshalSignature marshals sm2 signatures and fails the test on error.
func marshalSignature(t *testing.T, sig sm2Sign) []byte {
	t.Helper()
	b, err := asn1.Marshal(sig)
	if err != nil {
		t.Fatalf("Failed to marshal signature: %v", err)
	}
	return b
}

// TestEncrypt tests the Encrypt function
func TestEncrypt(t *testing.T) {
	pub := generateTestPublicKey(t)

	t.Run("normal encryption", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if len(ciphertext) == 0 {
			t.Fatal("Ciphertext is empty")
		}
		if ciphertext[0] != 0x04 {
			t.Fatal("Invalid ciphertext format")
		}
	})

	t.Run("random is nil", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(nil, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if len(ciphertext) == 0 {
			t.Fatal("Ciphertext is empty")
		}
	})

	t.Run("pub is nil", func(t *testing.T) {
		plaintext := []byte("hello world")
		_, err := Encrypt(rand.Reader, nil, plaintext, C1C2C3, 4)
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("Expected error io.ErrUnexpectedEOF, got: %v", err)
		}
	})

	t.Run("plaintext is empty", func(t *testing.T) {
		ciphertext, err := Encrypt(rand.Reader, pub, []byte{}, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if len(ciphertext) != 1 || ciphertext[0] != 0x04 {
			t.Fatalf("Empty plaintext encryption result is wrong: %v", ciphertext)
		}
	})

	t.Run("C1C3C2 order", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C3C2, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if len(ciphertext) == 0 {
			t.Fatal("Ciphertext is empty")
		}
	})

	t.Run("window parameter range", func(t *testing.T) {
		plaintext := []byte("hello world")
		for w := 1; w <= 7; w++ {
			ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, w)
			if err != nil {
				t.Fatalf("window=%d encryption failed: %v", w, err)
			}
			if len(ciphertext) == 0 {
				t.Fatalf("window=%d ciphertext is empty", w)
			}
		}
	})
}

// TestDecrypt tests the Decrypt function
func TestDecrypt(t *testing.T) {
	priv, pub := generateTestKeyPair(t)

	t.Run("normal decryption", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypted, err := Decrypt(priv, ciphertext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch: expected %s, got %s", plaintext, decrypted)
		}
	})

	t.Run("C1C3C2 order", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C3C2, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypted, err := Decrypt(priv, ciphertext, C1C3C2, 4)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch: expected %s, got %s", plaintext, decrypted)
		}
	})

	t.Run("priv is nil", func(t *testing.T) {
		ciphertext := []byte{0x04, 0x01, 0x02, 0x03}
		_, err := Decrypt(nil, ciphertext, C1C2C3, 4)
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("Expected error io.ErrUnexpectedEOF, got: %v", err)
		}
	})

	t.Run("ciphertext is empty", func(t *testing.T) {
		_, err := Decrypt(priv, []byte{}, C1C2C3, 4)
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("Expected error io.ErrUnexpectedEOF, got: %v", err)
		}
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		_, err := Decrypt(priv, []byte{0x04, 0x01}, C1C2C3, 4)
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("Expected error io.ErrUnexpectedEOF, got: %v", err)
		}
	})

	t.Run("invalid ciphertext format", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		// Modify C3 part to make verification fail
		ciphertext[len(ciphertext)-1] ^= 0x01
		_, err = Decrypt(priv, ciphertext, C1C2C3, 4)
		if err == nil {
			t.Fatal("Expected error, but decryption succeeded")
		}
	})

	t.Run("verification failed", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Modify C3 part to make verification fail
		ciphertext[len(ciphertext)-1] ^= 0x01

		_, err = Decrypt(priv, ciphertext, C1C2C3, 4)
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("Expected error io.ErrUnexpectedEOF, got: %v", err)
		}
	})

	t.Run("window parameter range", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		for w := 1; w <= 7; w++ {
			decrypted, err := Decrypt(priv, ciphertext, C1C2C3, w)
			if err != nil {
				t.Fatalf("window=%d decryption failed: %v", w, err)
			}
			if string(decrypted) != string(plaintext) {
				t.Fatalf("window=%d decryption result mismatch", w)
			}
		}
	})

	t.Run("ciphertext without 0x04 prefix", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		// Remove 0x04 prefix - Decrypt handles this gracefully
		ciphertextWithoutPrefix := ciphertext[1:]
		decrypted, err := Decrypt(priv, ciphertextWithoutPrefix, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch: expected %s, got %s", plaintext, decrypted)
		}
	})

	t.Run("window less than 2", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		// window = 1 should not set window
		decrypted, err := Decrypt(priv, ciphertext, C1C2C3, 1)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch")
		}
	})

	t.Run("window greater than 6", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		// window = 7 should not set window
		decrypted, err := Decrypt(priv, ciphertext, C1C2C3, 7)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch")
		}
	})

	t.Run("negative n calculation", func(t *testing.T) {
		// Create a ciphertext that would result in negative n
		curve := NewCurve()
		coordLen := (curve.Params().BitSize + 7) / 8
		// Create ciphertext with length less than 2*coordLen+32
		invalidCiphertext := make([]byte, 2*coordLen+31)
		invalidCiphertext[0] = 0x04
		_, err := Decrypt(priv, invalidCiphertext, C1C2C3, 4)
		if err == nil {
			t.Fatal("Expected error for invalid ciphertext length")
		}
	})

	t.Run("C1C3C2 order with wrong C3", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C3C2, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Modify C3 part (which is in the middle for C1C3C2)
		curve := NewCurve()
		coordLen := (curve.Params().BitSize + 7) / 8
		// C3 starts at 2*coordLen for C1C3C2
		c3Start := 1 + 2*coordLen // +1 for 0x04 prefix
		if len(ciphertext) > c3Start+32 {
			ciphertext[c3Start] ^= 0x01
			_, err = Decrypt(priv, ciphertext, C1C3C2, 4)
			if err == nil {
				t.Fatal("Expected error, but decryption succeeded")
			}
		}
	})

	t.Run("C1C2C3 order with wrong C3 at end", func(t *testing.T) {
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Modify the last byte (C3 is at the end for C1C2C3)
		if len(ciphertext) > 1 {
			ciphertext[len(ciphertext)-2] ^= 0x01 // -2 because last byte might be part of C3
			_, err = Decrypt(priv, ciphertext, C1C2C3, 4)
			if err == nil {
				t.Fatal("Expected error, but decryption succeeded")
			}
		}
	})

	t.Run("decrypt with ciphertext starting with non-0x04", func(t *testing.T) {
		// Create a valid ciphertext and remove 0x04 prefix manually
		plaintext := []byte("hello world")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		// Remove 0x04 prefix - Decrypt handles this gracefully
		ciphertextWithoutPrefix := ciphertext[1:]
		decrypted, err := Decrypt(priv, ciphertextWithoutPrefix, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch: expected %s, got %s", plaintext, decrypted)
		}
	})

	t.Run("decrypt with ciphertext not starting with 0x04", func(t *testing.T) {
		// Test that Decrypt handles ciphertext without 0x04 prefix
		// Encrypt always returns ciphertext starting with 0x04, so we remove it
		plaintext := []byte("test")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		// Remove 0x04 prefix - Decrypt handles this gracefully
		ciphertextNoPrefix := ciphertext[1:]
		decrypted, err := Decrypt(priv, ciphertextNoPrefix, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch: expected %s, got %s", plaintext, decrypted)
		}
	})

	t.Run("decrypt with window outside range", func(t *testing.T) {
		// Test window < 2 and window > 6 branches
		plaintext := []byte("test")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		// Test window = 0 (outside range)
		decrypted, err := Decrypt(priv, ciphertext, C1C2C3, 0)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch")
		}
		// Test window = 1 (outside range)
		decrypted, err = Decrypt(priv, ciphertext, C1C2C3, 1)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch")
		}
		// Test window = 7 (outside range)
		decrypted, err = Decrypt(priv, ciphertext, C1C2C3, 7)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decryption result mismatch")
		}
	})

	t.Run("decrypt ensuring all window branches", func(t *testing.T) {
		plaintext := []byte("test")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C2C3, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		// Test all window values to ensure all branches are covered
		for w := 0; w <= 10; w++ {
			decrypted, err := Decrypt(priv, ciphertext, C1C2C3, w)
			if err != nil {
				t.Fatalf("Decryption failed for window=%d: %v", w, err)
			}
			if string(decrypted) != string(plaintext) {
				t.Fatalf("Decryption result mismatch for window=%d", w)
			}
		}
	})
}

// TestSign tests the Sign function
func TestSign(t *testing.T) {
	priv, _ := generateTestKeyPair(t)
	message := []byte("hello world")
	digest := generateTestDigest(message)

	t.Run("normal signing", func(t *testing.T) {
		sig, err := Sign(rand.Reader, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}
		if len(sig) == 0 {
			t.Fatal("Signature is empty")
		}
	})

	t.Run("random is nil", func(t *testing.T) {
		sig, err := Sign(nil, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}
		if len(sig) == 0 {
			t.Fatal("Signature is empty")
		}
	})

	t.Run("invalid private key d is 0", func(t *testing.T) {
		curve := NewCurve()
		invalidPriv := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve},
			D:         big.NewInt(0),
		}
		_, err := Sign(rand.Reader, invalidPriv, digest, nil)
		if err == nil {
			t.Fatal("Expected error, but signing succeeded")
		}
	})

	t.Run("invalid private key d greater than or equal to n", func(t *testing.T) {
		curve := NewCurve()
		params := curve.Params()
		invalidPriv := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve},
			D:         new(big.Int).Set(params.N),
		}
		_, err := Sign(rand.Reader, invalidPriv, digest, nil)
		if err == nil {
			t.Fatal("Expected error, but signing succeeded")
		}
	})

	t.Run("signing retry loop", func(t *testing.T) {
		// This test ensures the signing function can handle retry cases
		// By signing multiple times to increase probability of triggering retry conditions
		for i := 0; i < 10; i++ {
			testMessage := []byte("test message " + string(rune(i+'0')))
			testDigest := generateTestDigest(testMessage)
			sig, err := Sign(rand.Reader, priv, testDigest, nil)
			if err != nil {
				t.Fatalf("Signing attempt %d failed: %v", i, err)
			}
			if len(sig) == 0 {
				t.Fatalf("Signature %d is empty", i)
			}
		}
	})

	t.Run("RandScalar error", func(t *testing.T) {
		errorReader := &errorReader{}
		_, err := Sign(errorReader, priv, digest, nil)
		if err == nil {
			t.Fatal("Expected error, but signing succeeded")
		}
	})
}

// TestVerify tests the Verify function
func TestVerify(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	message := []byte("hello world")
	digest := generateTestDigest(message)

	t.Run("normal verification", func(t *testing.T) {
		sig, err := Sign(rand.Reader, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		valid := Verify(pub, digest, nil, sig)
		if !valid {
			t.Fatal("Verification failed")
		}
	})

	t.Run("invalid ASN1 format", func(t *testing.T) {
		invalidSig := []byte{0xff, 0xff, 0xff}
		valid := Verify(pub, digest, nil, invalidSig)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("r is 0", func(t *testing.T) {
		// Create a signature with r=0
		sig := sm2Sign{R: big.NewInt(0), S: big.NewInt(1)}
		sigBytes := marshalSignature(t, sig)
		var parsed sm2Sign
		if _, err := asn1.Unmarshal(sigBytes, &parsed); err != nil {
			t.Fatalf("Failed to unmarshal signature: %v", err)
		}
		if parsed.R.Sign() != 0 || parsed.S.Sign() <= 0 {
			t.Fatalf("Unexpected signature values r=%v s=%v", parsed.R, parsed.S)
		}
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("r greater than or equal to n", func(t *testing.T) {
		curve := NewCurve()
		params := curve.Params()
		sig := sm2Sign{R: new(big.Int).Set(params.N), S: big.NewInt(1)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("r is negative", func(t *testing.T) {
		sig := sm2Sign{R: big.NewInt(-1), S: big.NewInt(1)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("r is zero", func(t *testing.T) {
		sig := sm2Sign{R: big.NewInt(0), S: big.NewInt(1)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("r sign is zero", func(t *testing.T) {
		// Test r.Sign() <= 0 case
		sig := sm2Sign{R: big.NewInt(0), S: big.NewInt(1)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("s is 0", func(t *testing.T) {
		sig := sm2Sign{R: big.NewInt(1), S: big.NewInt(0)}
		sigBytes := marshalSignature(t, sig)
		var parsed sm2Sign
		if _, err := asn1.Unmarshal(sigBytes, &parsed); err != nil {
			t.Fatalf("Failed to unmarshal signature: %v", err)
		}
		if parsed.R.Sign() <= 0 || parsed.S.Sign() != 0 {
			t.Fatalf("Unexpected signature values r=%v s=%v", parsed.R, parsed.S)
		}
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("s greater than or equal to n", func(t *testing.T) {
		curve := NewCurve()
		params := curve.Params()
		sig := sm2Sign{R: big.NewInt(1), S: new(big.Int).Set(params.N)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("s is negative", func(t *testing.T) {
		sig := sm2Sign{R: big.NewInt(1), S: big.NewInt(-1)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("s is zero", func(t *testing.T) {
		sig := sm2Sign{R: big.NewInt(1), S: big.NewInt(0)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("s sign is zero", func(t *testing.T) {
		// Test s.Sign() <= 0 case
		sig := sm2Sign{R: big.NewInt(1), S: big.NewInt(0)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("t is 0", func(t *testing.T) {
		curve := NewCurve()
		params := curve.Params()
		// Create r + s = n case, making t = 0
		r := new(big.Int).Sub(params.N, big.NewInt(1))
		s := big.NewInt(1)
		sig := sm2Sign{R: r, S: s}
		sigBytes := marshalSignature(t, sig)
		var parsed sm2Sign
		if _, err := asn1.Unmarshal(sigBytes, &parsed); err != nil {
			t.Fatalf("Failed to unmarshal signature: %v", err)
		}
		sum := new(big.Int).Add(parsed.R, parsed.S)
		sum.Mod(sum, params.N)
		if sum.Sign() != 0 {
			t.Fatalf("Expected t to be zero, got %v", sum)
		}
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("wrong digest", func(t *testing.T) {
		sig, err := Sign(rand.Reader, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		wrongDigest := generateTestDigest([]byte("wrong message"))
		valid := Verify(pub, wrongDigest, nil, sig)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("verification with wrong public key", func(t *testing.T) {
		sig, err := Sign(rand.Reader, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		// Generate a different key pair
		_, wrongPub := generateTestKeyPair(t)
		valid := Verify(wrongPub, digest, nil, sig)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("verification with valid signature but wrong digest", func(t *testing.T) {
		// Create a valid signature for one digest
		digest1 := generateTestDigest([]byte("message1"))
		sig, err := Sign(rand.Reader, priv, digest1, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		// Verify with a different digest (this should fail because v != r)
		digest2 := generateTestDigest([]byte("message2"))
		valid := Verify(pub, digest2, nil, sig)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("verification with modified signature", func(t *testing.T) {
		sig, err := Sign(rand.Reader, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		// Modify the signature slightly
		if len(sig) > 10 {
			sig[len(sig)-1] ^= 0x01
			valid := Verify(pub, digest, nil, sig)
			if valid {
				t.Fatal("Expected verification to fail, but it succeeded")
			}
		}
	})

	t.Run("verification with completely wrong signature values", func(t *testing.T) {
		// Create a signature with completely wrong r and s values
		// This should cause v != r in the verification
		curve := NewCurve()
		params := curve.Params()
		// Use valid range but wrong values
		wrongR := new(big.Int).Sub(params.N, big.NewInt(100))
		wrongS := new(big.Int).Sub(params.N, big.NewInt(200))
		sig := sm2Sign{R: wrongR, S: wrongS}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("verification with signature where v != r", func(t *testing.T) {
		// Create a signature for one message
		digest1 := generateTestDigest([]byte("message one"))
		sig, err := Sign(rand.Reader, priv, digest1, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		// Verify with a completely different digest
		// This should result in v != r
		digest2 := generateTestDigest([]byte("completely different message"))
		valid := Verify(pub, digest2, nil, sig)
		if valid {
			t.Fatal("Expected verification to fail (v != r), but it succeeded")
		}
	})

	t.Run("verification where v != r with wrong digest", func(t *testing.T) {
		// Create signature for one digest
		digest1 := generateTestDigest([]byte("original message"))
		sig, err := Sign(rand.Reader, priv, digest1, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		// Verify with different digest - this will cause v != r
		digest2 := generateTestDigest([]byte("different message"))
		valid := Verify(pub, digest2, nil, sig)
		if valid {
			t.Fatal("Expected verification to fail (v != r), but it succeeded")
		}
	})

	t.Run("verification where v != r with modified signature", func(t *testing.T) {
		// Create a valid signature
		sig, err := Sign(rand.Reader, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		// Unmarshal and modify the signature slightly
		var sign sm2Sign
		_, err = asn1.Unmarshal(sig, &sign)
		if err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		// Modify r slightly to cause v != r
		sign.R = new(big.Int).Add(sign.R, big.NewInt(1))
		modifiedSig := marshalSignature(t, sign)
		valid := Verify(pub, digest, nil, modifiedSig)
		if valid {
			t.Fatal("Expected verification to fail (v != r), but it succeeded")
		}
	})

	t.Run("verification ensuring all code paths execute", func(t *testing.T) {
		// Run multiple verifications to ensure all code paths are executed
		for i := 0; i < 100; i++ {
			testMsg := []byte("test message " + string(rune(i%10+'0')))
			testDigest := generateTestDigest(testMsg)
			sig, err := Sign(rand.Reader, priv, testDigest, nil)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}
			valid := Verify(pub, testDigest, nil, sig)
			if !valid {
				t.Fatalf("Verification failed for message %d", i)
			}
		}
	})

	t.Run("verification with r exactly equal to n-1", func(t *testing.T) {
		curve := NewCurve()
		params := curve.Params()
		// Test r = n - 1 (boundary case)
		r := new(big.Int).Sub(params.N, big.NewInt(1))
		s := big.NewInt(1)
		sig := sm2Sign{R: r, S: s}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		// This might succeed or fail depending on the signature validity
		_ = valid
	})

	t.Run("verification with s exactly equal to n-1", func(t *testing.T) {
		curve := NewCurve()
		params := curve.Params()
		// Test s = n - 1 (boundary case)
		r := big.NewInt(1)
		s := new(big.Int).Sub(params.N, big.NewInt(1))
		sig := sm2Sign{R: r, S: s}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		// This might succeed or fail depending on the signature validity
		_ = valid
	})

	t.Run("verification with r equal to 1", func(t *testing.T) {
		// Test r = 1 (boundary case)
		sig := sm2Sign{R: big.NewInt(1), S: big.NewInt(1)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		// This might succeed or fail depending on the signature validity
		_ = valid
	})

	t.Run("verification with s equal to 1", func(t *testing.T) {
		// Test s = 1 (boundary case)
		sig := sm2Sign{R: big.NewInt(1), S: big.NewInt(1)}
		sigBytes := marshalSignature(t, sig)
		valid := Verify(pub, digest, nil, sigBytes)
		// This might succeed or fail depending on the signature validity
		_ = valid
	})

	t.Run("verification ensuring all curve operations", func(t *testing.T) {
		// Ensure all curve operations (ScalarBaseMult, ScalarMult, Add) are executed
		// by running multiple successful verifications
		for i := 0; i < 200; i++ {
			testMsg := []byte("verify test " + string(rune(i%10+'0')))
			testDigest := generateTestDigest(testMsg)
			sig, err := Sign(rand.Reader, priv, testDigest, nil)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}
			valid := Verify(pub, testDigest, nil, sig)
			if !valid {
				t.Fatalf("Verification failed for message %d", i)
			}
		}
	})

	t.Run("decrypt ensuring all branches for C1C3C2 order", func(t *testing.T) {
		// Ensure C1C3C2 order branch is fully covered
		plaintext := []byte("test message")
		ciphertext, err := Encrypt(rand.Reader, pub, plaintext, C1C3C2, 4)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		// Test with 0x04 prefix
		decrypted1, err := Decrypt(priv, ciphertext, C1C3C2, 4)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted1) != string(plaintext) {
			t.Fatalf("Decryption result mismatch")
		}
		// Test without 0x04 prefix - Decrypt handles this gracefully
		decrypted2, err := Decrypt(priv, ciphertext[1:], C1C3C2, 4)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(decrypted2) != string(plaintext) {
			t.Fatalf("Decryption result mismatch")
		}
	})

	t.Run("verification with empty digest", func(t *testing.T) {
		emptyDigest := []byte{}
		sig, err := Sign(rand.Reader, priv, emptyDigest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}
		valid := Verify(pub, emptyDigest, nil, sig)
		// This might succeed or fail depending on implementation
		_ = valid
	})

	t.Run("verification with nil public key curve", func(t *testing.T) {
		// This test ensures curve operations are covered
		sig, err := Sign(rand.Reader, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}
		// Use a different key pair (should fail)
		_, wrongPub := generateTestKeyPair(t)
		valid := Verify(wrongPub, digest, nil, sig)
		if valid {
			t.Fatal("Expected verification to fail with different key")
		}
	})

	t.Run("verification ensuring all curve operations execute", func(t *testing.T) {
		// Create multiple signatures and verify them to ensure all code paths are executed
		for i := 0; i < 50; i++ {
			testMsg := []byte("test message " + string(rune(i%10+'0')))
			testDigest := generateTestDigest(testMsg)
			sig, err := Sign(rand.Reader, priv, testDigest, nil)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}
			valid := Verify(pub, testDigest, nil, sig)
			if !valid {
				t.Fatalf("Verification failed for message %d", i)
			}
		}
	})

	t.Run("verification with various digest sizes", func(t *testing.T) {
		// Test with different digest sizes to ensure all code paths
		digestSizes := [][]byte{
			{0x00},
			{0x00, 0x01, 0x02, 0x03},
			make([]byte, 32),
			make([]byte, 64),
		}
		for i, testDigest := range digestSizes {
			// Fill with some data
			for j := range testDigest {
				testDigest[j] = byte(i + j)
			}
			sig, err := Sign(rand.Reader, priv, testDigest, nil)
			if err != nil {
				t.Fatalf("Signing failed for digest size %d: %v", len(testDigest), err)
			}
			valid := Verify(pub, testDigest, nil, sig)
			if !valid {
				t.Fatalf("Verification failed for digest size %d", len(testDigest))
			}
		}
	})
}

// TestPadLeft tests the padLeft function
func TestPadLeft(t *testing.T) {
	t.Run("needs padding", func(t *testing.T) {
		b := []byte{0x01, 0x02}
		padded := padLeft(b, 4)
		if len(padded) != 4 {
			t.Fatalf("Expected length 4, got %d", len(padded))
		}
		if padded[0] != 0 || padded[1] != 0 || padded[2] != 0x01 || padded[3] != 0x02 {
			t.Fatalf("Padding result is wrong: %v", padded)
		}
	})

	t.Run("no padding needed", func(t *testing.T) {
		b := []byte{0x01, 0x02, 0x03, 0x04}
		padded := padLeft(b, 4)
		if len(padded) != 4 {
			t.Fatalf("Expected length 4, got %d", len(padded))
		}
		if !bytesEqual(padded, b) {
			t.Fatalf("Should not modify original data: %v vs %v", padded, b)
		}
	})

	t.Run("length greater than size", func(t *testing.T) {
		b := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		padded := padLeft(b, 4)
		if len(padded) != 5 {
			t.Fatalf("Expected length 5, got %d", len(padded))
		}
		if !bytesEqual(padded, b) {
			t.Fatalf("Should not modify original data: %v vs %v", padded, b)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		b := []byte{}
		padded := padLeft(b, 4)
		if len(padded) != 4 {
			t.Fatalf("Expected length 4, got %d", len(padded))
		}
		for i := 0; i < 4; i++ {
			if padded[i] != 0 {
				t.Fatalf("Expected all zeros, got %v", padded)
			}
		}
	})
}

// TestSm3KDF tests the sm3KDF function
func TestSm3KDF(t *testing.T) {
	t.Run("normal KDF", func(t *testing.T) {
		parts := [][]byte{[]byte("part1"), []byte("part2")}
		out, ok := sm3KDF(32, parts...)
		if !ok {
			t.Fatal("KDF failed")
		}
		if len(out) != 32 {
			t.Fatalf("Expected length 32, got %d", len(out))
		}
	})

	t.Run("length not multiple of 32", func(t *testing.T) {
		parts := [][]byte{[]byte("part1")}
		out, ok := sm3KDF(50, parts...)
		if !ok {
			t.Fatal("KDF failed")
		}
		if len(out) != 50 {
			t.Fatalf("Expected length 50, got %d", len(out))
		}
	})

	t.Run("multiple blocks", func(t *testing.T) {
		parts := [][]byte{[]byte("part1")}
		out, ok := sm3KDF(100, parts...)
		if !ok {
			t.Fatal("KDF failed")
		}
		if len(out) != 100 {
			t.Fatalf("Expected length 100, got %d", len(out))
		}
	})

	t.Run("empty parts", func(t *testing.T) {
		out, ok := sm3KDF(32)
		if !ok {
			t.Fatal("KDF failed")
		}
		if len(out) != 32 {
			t.Fatalf("Expected length 32, got %d", len(out))
		}
	})

	t.Run("single block exact", func(t *testing.T) {
		parts := [][]byte{[]byte("test")}
		out, ok := sm3KDF(32, parts...)
		if !ok {
			t.Fatal("KDF failed")
		}
		if len(out) != 32 {
			t.Fatalf("Expected length 32, got %d", len(out))
		}
	})

	t.Run("large length", func(t *testing.T) {
		parts := [][]byte{[]byte("part1"), []byte("part2")}
		out, ok := sm3KDF(200, parts...)
		if !ok {
			t.Fatal("KDF failed")
		}
		if len(out) != 200 {
			t.Fatalf("Expected length 200, got %d", len(out))
		}
	})
}

// TestBytesEqual tests the bytesEqual function
func TestBytesEqual(t *testing.T) {
	t.Run("equal", func(t *testing.T) {
		a := []byte{0x01, 0x02, 0x03}
		b := []byte{0x01, 0x02, 0x03}
		if !bytesEqual(a, b) {
			t.Fatal("Expected equal")
		}
	})

	t.Run("not equal", func(t *testing.T) {
		a := []byte{0x01, 0x02, 0x03}
		b := []byte{0x01, 0x02, 0x04}
		if bytesEqual(a, b) {
			t.Fatal("Expected not equal")
		}
	})

	t.Run("different lengths", func(t *testing.T) {
		a := []byte{0x01, 0x02}
		b := []byte{0x01, 0x02, 0x03}
		if bytesEqual(a, b) {
			t.Fatal("Expected not equal")
		}
	})

	t.Run("empty slices", func(t *testing.T) {
		a := []byte{}
		b := []byte{}
		if !bytesEqual(a, b) {
			t.Fatal("Expected equal")
		}
	})

	t.Run("one empty one not", func(t *testing.T) {
		a := []byte{}
		b := []byte{0x01}
		if bytesEqual(a, b) {
			t.Fatal("Expected not equal")
		}
	})
}

// TestEncrypt_ErrorPaths tests error paths in Encrypt
func TestEncrypt_ErrorPaths(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	// Create a reader that always returns an error
	errorReader := &errorReader{}

	t.Run("RandScalar failure", func(t *testing.T) {
		plaintext := []byte("hello world")
		_, err := Encrypt(errorReader, pub, plaintext, C1C2C3, 4)
		if err == nil {
			t.Fatal("Expected error, but encryption succeeded")
		}
	})
}

// errorReader is an io.Reader that always returns an error
type errorReader struct{}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

// TestSign_RetryLogic tests retry logic in Sign
func TestSign_RetryLogic(t *testing.T) {
	priv, _ := generateTestKeyPair(t)

	// Test retry logic by signing multiple times
	// Note: Since retry logic depends on randomness, we increase probability by multiple executions
	// Increase test count to improve probability of triggering retry conditions
	for i := 0; i < 100; i++ {
		message := []byte("test message " + string(rune(i%10+'0')))
		digest := generateTestDigest(message)
		sig, err := Sign(rand.Reader, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing attempt %d failed: %v", i, err)
		}
		if len(sig) == 0 {
			t.Fatalf("Signature %d is empty", i)
		}
	}
}

// TestSign_RetryConditions tests various retry conditions in Sign
func TestSign_RetryConditions(t *testing.T) {
	priv, _ := generateTestKeyPair(t)
	curve := NewCurve()
	params := curve.Params()

	// Test various conditions that might cause retries
	// Note: These conditions are hard to trigger deterministically, but multiple random tests increase probability
	for i := 0; i < 500; i++ {
		message := []byte("test message " + string(rune(i%10+'0')))
		digest := generateTestDigest(message)
		sig, err := Sign(rand.Reader, priv, digest, nil)
		if err != nil {
			t.Fatalf("Signing attempt %d failed: %v", i, err)
		}
		if len(sig) == 0 {
			t.Fatalf("Signature %d is empty", i)
		}

		// Verify signature validity
		var sign sm2Sign
		_, err = asn1.Unmarshal(sig, &sign)
		if err != nil {
			t.Fatalf("Signature %d parsing failed: %v", i, err)
		}

		// Verify r and s validity
		if sign.R.Sign() <= 0 || sign.R.Cmp(params.N) >= 0 {
			t.Fatalf("Signature %d: r is invalid", i)
		}
		if sign.S.Sign() <= 0 || sign.S.Cmp(params.N) >= 0 {
			t.Fatalf("Signature %d: s is invalid", i)
		}
	}
}

// TestVerify_ErrorPaths tests various error paths in Verify
func TestVerify_ErrorPaths(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	message := []byte("test message")
	digest := generateTestDigest(message)

	t.Run("invalid signature format", func(t *testing.T) {
		invalidSig := []byte{0x30, 0x05} // Invalid ASN.1 structure
		valid := Verify(pub, digest, nil, invalidSig)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})

	t.Run("signature with wrong digest", func(t *testing.T) {
		// Create a valid signature but verify with wrong digest
		priv, _ := generateTestKeyPair(t)
		correctDigest := generateTestDigest([]byte("correct message"))
		sig, err := Sign(rand.Reader, priv, correctDigest, nil)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}
		wrongDigest := generateTestDigest([]byte("wrong message"))
		valid := Verify(pub, wrongDigest, nil, sig)
		if valid {
			t.Fatal("Expected verification to fail, but it succeeded")
		}
	})
}

// TestEncryptDecrypt_Integration tests complete encrypt-decrypt flow
func TestEncryptDecrypt_Integration(t *testing.T) {
	priv, pub := generateTestKeyPair(t)

	testCases := []struct {
		name      string
		plaintext []byte
		order     CipherOrder
		window    int
	}{
		{"short text C1C2C3", []byte("hello"), C1C2C3, 4},
		{"short text C1C3C2", []byte("hello"), C1C3C2, 4},
		{"long text C1C2C3", []byte("hello world this is a longer message"), C1C2C3, 4},
		{"long text C1C3C2", []byte("hello world this is a longer message"), C1C3C2, 4},
		{"window2", []byte("test"), C1C2C3, 2},
		{"window3", []byte("test"), C1C2C3, 3},
		{"window5", []byte("test"), C1C2C3, 5},
		{"window6", []byte("test"), C1C2C3, 6},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := Encrypt(rand.Reader, pub, tc.plaintext, tc.order, tc.window)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := Decrypt(priv, ciphertext, tc.order, tc.window)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytesEqual(decrypted, tc.plaintext) {
				t.Fatalf("Decryption result mismatch: expected %v, got %v", tc.plaintext, decrypted)
			}
		})
	}
}

// TestSignVerify_Integration tests complete sign-verify flow
func TestSignVerify_Integration(t *testing.T) {
	priv, pub := generateTestKeyPair(t)

	testCases := []struct {
		name    string
		message []byte
	}{
		{"short message", []byte("hello")},
		{"long message", []byte("hello world this is a longer message")},
		{"empty message", []byte{}},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			digest := generateTestDigest(tc.message)
			sig, err := Sign(rand.Reader, priv, digest, nil)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			valid := Verify(pub, digest, nil, sig)
			if !valid {
				t.Fatal("Verification failed")
			}
		})
	}
}

// TestInt2Bytes tests the Int2Bytes function (moved to internal/utils)
func TestInt2Bytes(t *testing.T) {
	t.Run("normal conversion", func(t *testing.T) {
		x := 1234567890
		b := utils.Int2Bytes(x)
		if len(b) != 4 {
			t.Fatalf("Expected length 4, got %d", len(b))
		}
	})

	t.Run("boundary values", func(t *testing.T) {
		testCases := []int{0, 1, 0x7FFFFFFF, 0xFFFFFFFF}
		for _, x := range testCases {
			b := utils.Int2Bytes(x)
			if len(b) != 4 {
				t.Fatalf("x=%d: Expected length 4, got %d", x, len(b))
			}
		}
	})
}
