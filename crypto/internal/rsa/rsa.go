package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

// EncryptPKCS1v15WithPublicKey encrypts data with a public key using PKCS#1 v1.5 padding.
func EncryptPKCS1v15WithPublicKey(random io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(random, pub, msg)
}

// EncryptOAEPWithPublicKey encrypts data with a public key using OAEP padding.
func EncryptOAEPWithPublicKey(hash hash.Hash, random io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(hash, random, pub, msg, nil)
}

// EncryptPKCS1v15WithPrivateKey encrypts data with a private key using PKCS#1 v1.5 padding.
func EncryptPKCS1v15WithPrivateKey(random io.Reader, pri *rsa.PrivateKey, msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(random, &pri.PublicKey, msg)
}

// EncryptOAEPWithPrivateKey encrypts data with a private key using OAEP padding.
func EncryptOAEPWithPrivateKey(hash hash.Hash, random io.Reader, pri *rsa.PrivateKey, msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(hash, random, &pri.PublicKey, msg, nil)
}

// DecryptPKCS1v15WithPublicKey decrypts data with a public key using PKCS#1 v1.5 padding.
func DecryptPKCS1v15WithPublicKey(pub *rsa.PublicKey, ciphertext []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}
	if pub.N == nil || pub.E == 0 {
		return nil, errors.New("invalid public key")
	}

	k := pub.Size()
	if len(ciphertext) != k {
		return nil, rsa.ErrDecryption
	}

	c := new(big.Int).SetBytes(ciphertext)
	if c.Cmp(pub.N) >= 0 { // ciphertext must be smaller than modulus N
		return nil, rsa.ErrDecryption
	}
	m := new(big.Int).Exp(c, big.NewInt(int64(pub.E)), pub.N)

	em := make([]byte, k)
	mBytes := m.Bytes()
	copy(em[len(em)-len(mBytes):], mBytes) // right-align per PKCS#1

	valid := subtle.ConstantTimeByteEq(em[0], 0x00)
	valid &= subtle.ConstantTimeByteEq(em[1], 0x01)
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}

	sepIndex := -1
	for i := 2; i < len(em); i++ {
		if em[i] == 0x00 {
			sepIndex = i
			break
		}
	}

	if sepIndex == -1 || sepIndex < 10 {
		return nil, rsa.ErrDecryption
	}

	for i := 2; i < sepIndex; i++ {
		valid &= subtle.ConstantTimeByteEq(em[i], 0xFF)
	}
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}

	if sepIndex+1 >= len(em) {
		return nil, rsa.ErrDecryption
	}
	return em[sepIndex+1:], nil
}

// DecryptOAEPWithPublicKey decrypts data with a public key using OAEP padding.
func DecryptOAEPWithPublicKey(hash hash.Hash, pub *rsa.PublicKey, ciphertext []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}
	if pub.N == nil || pub.E == 0 {
		return nil, errors.New("invalid public key")
	}
	if hash == nil {
		return nil, errors.New("hash function is nil")
	}

	k := pub.Size()
	if len(ciphertext) != k {
		return nil, rsa.ErrDecryption
	}

	// Perform modular exponentiation: c^e mod n
	c := new(big.Int).SetBytes(ciphertext)
	if c.Cmp(pub.N) >= 0 {
		return nil, rsa.ErrDecryption
	}

	m := new(big.Int).Exp(c, big.NewInt(int64(pub.E)), pub.N)

	// Reconstruct encoded message bytes
	em := make([]byte, k)
	mBytes := m.Bytes()
	copy(em[len(em)-len(mBytes):], mBytes)

	// OAEP unpadding (based on crypto/rsa implementation)
	hash.Reset()
	hashSize := hash.Size()

	// Check encoded message length
	if len(em) < hashSize*2+2 {
		return nil, rsa.ErrDecryption
	}

	// First byte must be 0 (constant-time check to avoid timing leaks)
	valid := subtle.ConstantTimeByteEq(em[0], 0x00)
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}

	// Split maskedSeed and maskedDB
	maskedSeed := em[1 : hashSize+1]
	maskedDB := em[hashSize+1:]

	// Recover seed via MGF1
	seed := make([]byte, hashSize)
	copy(seed, maskedSeed)
	mgf1(seed, hash, maskedDB)

	// Recover DB via MGF1
	db := make([]byte, len(maskedDB))
	copy(db, maskedDB)
	mgf1(db, hash, seed)

	// Validate lHash
	lHash := db[:hashSize]
	hash.Reset()
	hash.Write(nil) // empty label
	expectedLHash := hash.Sum(nil)

	if !equalBytes(lHash, expectedLHash) {
		return nil, rsa.ErrDecryption
	}

	// Locate 0x01 separator
	lookingForIndex := -1
	for i := hashSize; i < len(db); i++ {
		if db[i] == 0x01 {
			lookingForIndex = i
			break
		}
	}

	if lookingForIndex == -1 {
		return nil, rsa.ErrDecryption
	}

	// Constant-time verify padding string (db[hashSize:lookingForIndex]) is all 0x00
	// This prevents timing attacks that could reveal the separator position
	for i := hashSize; i < lookingForIndex; i++ {
		valid &= subtle.ConstantTimeByteEq(db[i], 0x00)
	}
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}

	// Return unpadded message
	return db[lookingForIndex+1:], nil
}

// DecryptPKCS1v15WithPrivateKey decrypts data with a private key using PKCS#1 v1.5 padding.
func DecryptPKCS1v15WithPrivateKey(random io.Reader, pri *rsa.PrivateKey, msg []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(random, pri, msg)
}

// DecryptOAEPWithPrivateKey decrypts data with a private key using OAEP padding.
func DecryptOAEPWithPrivateKey(hash hash.Hash, random io.Reader, pri *rsa.PrivateKey, msg []byte) ([]byte, error) {
	return rsa.DecryptOAEP(hash, random, pri, msg, nil)
}

// pkcs1v15HashPrefixes holds ASN.1 DigestInfo prefixes for supported hashes.
var pkcs1v15HashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:        {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:       {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:     {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:     {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:     {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.SHA512_224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA512_256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA3_224:   {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA3_256:   {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA3_384:   {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA3_512:   {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:    {},
	crypto.RIPEMD160:  {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

// SignPKCS1v15WithPublicKey signs data with a public key using PKCS#1 v1.5 padding.
func SignPKCS1v15WithPublicKey(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}
	if pub.N == nil || pub.E == 0 {
		return nil, errors.New("invalid public key")
	}

	if hash != crypto.Hash(0) && len(hashed) != hash.Size() {
		return nil, errors.New("input must be hashed message")
	}

	var prefix []byte
	if hash != crypto.Hash(0) {
		var ok bool
		prefix, ok = pkcs1v15HashPrefixes[hash]
		if !ok {
			return nil, errors.New("unsupported hash function")
		}
	}

	k := pub.Size()
	tLen := len(prefix) + len(hashed)
	if k < tLen+11 {
		return nil, rsa.ErrMessageTooLong
	}

	em := make([]byte, k)
	em[0] = 0x00 // block type: signature
	em[1] = 0x01
	psLen := k - tLen - 3
	if psLen < 8 {
		return nil, rsa.ErrMessageTooLong
	}
	for i := 2; i < 2+psLen; i++ {
		em[i] = 0xff
	}
	em[2+psLen] = 0x00

	copy(em[k-tLen:], prefix)
	copy(em[k-len(hashed):], hashed)

	m := new(big.Int).SetBytes(em)
	if m.Cmp(pub.N) >= 0 {
		return nil, rsa.ErrMessageTooLong
	}

	s := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	signature := make([]byte, k)
	sBytes := s.Bytes()
	copy(signature[k-len(sBytes):], sBytes)

	return signature, nil
}

// SignPSSWithPublicKey signs data with a public key using PSS padding.
func SignPSSWithPublicKey(random io.Reader, pub *rsa.PublicKey, hash crypto.Hash, digest []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}
	if pub.N == nil || pub.E == 0 {
		return nil, errors.New("invalid public key")
	}
	if hash == crypto.Hash(0) || !hash.Available() {
		return nil, errors.New("unsupported hash function")
	}

	emBits := pub.N.BitLen() - 1
	saltLength := (emBits+7)/8 - hash.Size() - 2
	if saltLength < 0 {
		return nil, rsa.ErrMessageTooLong
	}

	if len(digest) != hash.Size() {
		return nil, errors.New("digest length must match hash size")
	}

	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, err
	}

	em, err := emsaPSSEncode(digest, emBits, salt, hash.New())
	if err != nil {
		return nil, err
	}

	k := pub.Size()
	if len(em) < k {
		padded := make([]byte, k)
		copy(padded[k-len(em):], em)
		em = padded
	}

	m := new(big.Int).SetBytes(em)
	if m.Cmp(pub.N) >= 0 {
		return nil, rsa.ErrMessageTooLong
	}

	s := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	signature := make([]byte, k)
	sBytes := s.Bytes()
	copy(signature[k-len(sBytes):], sBytes)

	return signature, nil
}

// SignPKCS1v15WithPrivateKey signs data with a private key using PKCS#1 v1.5 padding.
func SignPKCS1v15WithPrivateKey(random io.Reader, pri *rsa.PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(random, pri, hash, hashed)
}

// SignPSSWithPrivateKey signs data with a private key using PSS padding.
func SignPSSWithPrivateKey(random io.Reader, pri *rsa.PrivateKey, hash crypto.Hash, digest []byte) ([]byte, error) {
	return rsa.SignPSS(random, pri, hash, digest, nil)
}

// VerifyPKCS1v15WithPublicKey verifies a PKCS#1 v1.5 signature with a public key.
func VerifyPKCS1v15WithPublicKey(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sign []byte) error {
	return rsa.VerifyPKCS1v15(pub, hash, hashed, sign)
}

// VerifyPSSWithPublicKey verifies a PSS signature with a public key.
func VerifyPSSWithPublicKey(pub *rsa.PublicKey, hash crypto.Hash, digest []byte, sign []byte) error {
	return rsa.VerifyPSS(pub, hash, digest, sign, nil)
}

// VerifyPKCS1v15WithPrivateKey verifies a PKCS#1 v1.5 signature with a private key.
func VerifyPKCS1v15WithPrivateKey(pri *rsa.PrivateKey, hash crypto.Hash, hashed []byte, sign []byte) error {
	return rsa.VerifyPKCS1v15(&pri.PublicKey, hash, hashed, sign)
}

// VerifyPSSWithPrivateKey verifies a PSS signature with a private key.
func VerifyPSSWithPrivateKey(pri *rsa.PrivateKey, hash crypto.Hash, digest []byte, sign []byte) error {
	return rsa.VerifyPSS(&pri.PublicKey, hash, digest, sign, nil)
}

// mgf1 implements MGF1 (Mask Generation Function 1)
// Generates mask with hash and XORs into out
func mgf1(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Reset()
		hash.Write(seed)
		hash.Write(counter[:])
		digest = hash.Sum(digest[:0])

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}

		// Increment counter
		for i := len(counter) - 1; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}
}

// equalBytes compares two byte slices in constant time
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// emsaPSSEncode constructs an encoded message block for RSA-PSS signing.
func emsaPSSEncode(mHash []byte, emBits int, salt []byte, hash hash.Hash) ([]byte, error) {
	hLen := hash.Size()
	sLen := len(salt)
	emLen := (emBits + 7) / 8

	if len(mHash) != hLen {
		return nil, errors.New("input must be hashed with given hash")
	}

	if emLen < hLen+sLen+2 {
		return nil, rsa.ErrMessageTooLong
	}

	em := make([]byte, emLen)
	psLen := emLen - sLen - hLen - 2
	db := em[:psLen+1+sLen]
	hashPart := em[psLen+1+sLen : emLen-1]

	var prefix [8]byte
	hash.Write(prefix[:])
	hash.Write(mHash)
	hash.Write(salt)
	hashPart = hash.Sum(hashPart[:0])
	hash.Reset()

	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	mgf1(db, hash, hashPart)
	db[0] &= 0xff >> (8*emLen - emBits)

	em[emLen-1] = 0xbc
	return em, nil
}
