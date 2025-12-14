package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"math/big"
	"testing"
	"unsafe"

	"golang.org/x/crypto/sha3"
)

var errSaltFailure = errors.New("salt failure")

type failingReader struct {
	err error
}

func (f failingReader) Read(p []byte) (int, error) {
	return 0, f.err
}

type fixedSizeHash struct {
	size int
}

func (f fixedSizeHash) Write(p []byte) (int, error) { return len(p), nil }
func (f fixedSizeHash) Sum(b []byte) []byte {
	return append(b, make([]byte, f.size)...)
}
func (f fixedSizeHash) Reset()         {}
func (f fixedSizeHash) Size() int      { return f.size }
func (f fixedSizeHash) BlockSize() int { return 1 }

func mustKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func pkcs1CiphertextFromEM(priv *rsa.PrivateKey, em []byte) []byte {
	k := priv.PublicKey.Size()
	c := new(big.Int).Exp(new(big.Int).SetBytes(em), priv.D, priv.N)
	out := make([]byte, k)
	cb := c.Bytes()
	copy(out[k-len(cb):], cb)
	return out
}

func pkcs1Ciphertext(t *testing.T, priv *rsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	k := priv.PublicKey.Size()
	psLen := k - len(msg) - 3
	em := make([]byte, k)
	em[1] = 0x01
	for i := 2; i < 2+psLen; i++ {
		em[i] = 0xff
	}
	em[2+psLen] = 0x00
	copy(em[k-len(msg):], msg)
	return pkcs1CiphertextFromEM(priv, em)
}

func oaepDB(t *testing.T, h hash.Hash, k int, msg []byte) ([]byte, []byte) {
	t.Helper()
	h.Reset()
	lHash := h.Sum(nil)
	hLen := h.Size()
	db := make([]byte, k-hLen-1)
	copy(db[:hLen], lHash)
	psLen := len(db) - len(msg) - 1 - hLen
	if psLen < 0 {
		t.Fatalf("message too long for oaep test")
	}
	db[hLen+psLen] = 0x01
	copy(db[hLen+psLen+1:], msg)
	seed := make([]byte, hLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return db, seed
}

func oaepCiphertextFromDB(priv *rsa.PrivateKey, h hash.Hash, db, seed []byte) []byte {
	hLen := h.Size()
	maskedDB := append([]byte(nil), db...)
	maskedSeed := append([]byte(nil), seed...)
	mgf1(maskedDB, h, seed)
	mgf1(maskedSeed, h, maskedDB)

	em := make([]byte, priv.PublicKey.Size())
	em[0] = 0x00
	copy(em[1:1+hLen], maskedSeed)
	copy(em[1+hLen:], maskedDB)
	return pkcs1CiphertextFromEM(priv, em)
}

func oaepCiphertext(t *testing.T, priv *rsa.PrivateKey, h hash.Hash, msg []byte) ([]byte, []byte) {
	t.Helper()
	k := priv.PublicKey.Size()
	db, seed := oaepDB(t, h, k, msg)
	ct := oaepCiphertextFromDB(priv, h, db, seed)
	return ct, db
}

func TestEncryptDecryptWrappers(t *testing.T) {
	key := mustKey(t, 1024)
	msg := []byte("wrapper message")

	c1, err := EncryptPKCS1v15WithPublicKey(rand.Reader, &key.PublicKey, msg)
	if err != nil {
		t.Fatalf("encrypt pkcs1: %v", err)
	}
	p1, err := DecryptPKCS1v15WithPrivateKey(rand.Reader, key, c1)
	if err != nil {
		t.Fatalf("decrypt pkcs1: %v", err)
	}
	if !bytes.Equal(p1, msg) {
		t.Fatalf("pkcs1 mismatch")
	}

	c2, err := EncryptOAEPWithPublicKey(sha256.New(), rand.Reader, &key.PublicKey, msg)
	if err != nil {
		t.Fatalf("encrypt oaep: %v", err)
	}
	p2, err := DecryptOAEPWithPrivateKey(sha256.New(), rand.Reader, key, c2)
	if err != nil {
		t.Fatalf("decrypt oaep: %v", err)
	}
	if !bytes.Equal(p2, msg) {
		t.Fatalf("oaep mismatch")
	}

	c3, err := EncryptPKCS1v15WithPrivateKey(rand.Reader, key, msg)
	if err != nil {
		t.Fatalf("encrypt pkcs1 private: %v", err)
	}
	p3, err := DecryptPKCS1v15WithPrivateKey(rand.Reader, key, c3)
	if err != nil {
		t.Fatalf("decrypt pkcs1 private: %v", err)
	}
	if !bytes.Equal(p3, msg) {
		t.Fatalf("pkcs1 private mismatch")
	}

	c4, err := EncryptOAEPWithPrivateKey(sha256.New(), rand.Reader, key, msg)
	if err != nil {
		t.Fatalf("encrypt oaep private: %v", err)
	}
	p4, err := DecryptOAEPWithPrivateKey(sha256.New(), rand.Reader, key, c4)
	if err != nil {
		t.Fatalf("decrypt oaep private: %v", err)
	}
	if !bytes.Equal(p4, msg) {
		t.Fatalf("oaep private mismatch")
	}

	digest := sha256.Sum256(msg)
	sig1, err := SignPKCS1v15WithPrivateKey(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign pkcs1 private: %v", err)
	}
	if err := VerifyPKCS1v15WithPublicKey(&key.PublicKey, crypto.SHA256, digest[:], sig1); err != nil {
		t.Fatalf("verify pkcs1 private: %v", err)
	}
	if err := VerifyPKCS1v15WithPrivateKey(key, crypto.SHA256, digest[:], sig1); err != nil {
		t.Fatalf("verify pkcs1 private wrapper: %v", err)
	}

	sig2, err := SignPSSWithPrivateKey(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign pss private: %v", err)
	}
	if err := VerifyPSSWithPublicKey(&key.PublicKey, crypto.SHA256, digest[:], sig2); err != nil {
		t.Fatalf("verify pss private: %v", err)
	}
	if err := VerifyPSSWithPrivateKey(key, crypto.SHA256, digest[:], sig2); err != nil {
		t.Fatalf("verify pss private wrapper: %v", err)
	}
}

func TestDecryptPKCS1v15WithPublicKey(t *testing.T) {
	key := mustKey(t, 1024)
	msg := []byte("rsa public decrypt")
	cipher := pkcs1Ciphertext(t, key, msg)
	plain, err := DecryptPKCS1v15WithPublicKey(&key.PublicKey, cipher)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatalf("unexpected plaintext")
	}
}

func TestDecryptPKCS1v15WithPublicKeyErrors(t *testing.T) {
	key := mustKey(t, 1024)
	k := key.PublicKey.Size()
	msg := []byte("bad padding")

	if _, err := DecryptPKCS1v15WithPublicKey(nil, nil); err == nil {
		t.Fatalf("expected nil pub error")
	}

	if _, err := DecryptPKCS1v15WithPublicKey(&rsa.PublicKey{}, []byte{}); err == nil {
		t.Fatalf("expected invalid pub error")
	}

	if _, err := DecryptPKCS1v15WithPublicKey(&rsa.PublicKey{N: big.NewInt(5)}, []byte{}); err == nil {
		t.Fatalf("expected invalid pub error for zero exponent")
	}

	if _, err := DecryptPKCS1v15WithPublicKey(&key.PublicKey, []byte{1, 2, 3}); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected length error")
	}

	nBytes := key.N.Bytes()
	if len(nBytes) < k {
		pad := make([]byte, k)
		copy(pad[k-len(nBytes):], nBytes)
		nBytes = pad
	}
	if _, err := DecryptPKCS1v15WithPublicKey(&key.PublicKey, nBytes); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected modulus compare error")
	}

	zeroCipher := make([]byte, k)
	if _, err := DecryptPKCS1v15WithPublicKey(&key.PublicKey, zeroCipher); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected header error")
	}

	emNoSep := make([]byte, k)
	emNoSep[1] = 0x01
	for i := 2; i < k; i++ {
		emNoSep[i] = 0xff
	}
	if _, err := DecryptPKCS1v15WithPublicKey(&key.PublicKey, pkcs1CiphertextFromEM(key, emNoSep)); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected missing separator error")
	}

	emEarlySep := make([]byte, k)
	emEarlySep[1] = 0x01
	emEarlySep[4] = 0x00
	if _, err := DecryptPKCS1v15WithPublicKey(&key.PublicKey, pkcs1CiphertextFromEM(key, emEarlySep)); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected early separator error")
	}

	emBadPadding := make([]byte, k)
	emBadPadding[1] = 0x01
	for i := 2; i < 12; i++ {
		emBadPadding[i] = 0xff
	}
	emBadPadding[5] = 0x01
	emBadPadding[12] = 0x00
	copy(emBadPadding[k-len(msg):], msg)
	if _, err := DecryptPKCS1v15WithPublicKey(&key.PublicKey, pkcs1CiphertextFromEM(key, emBadPadding)); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected padding error")
	}

	emTrailingSep := make([]byte, k)
	emTrailingSep[1] = 0x01
	for i := 2; i < k-1; i++ {
		emTrailingSep[i] = 0xff
	}
	emTrailingSep[k-1] = 0x00
	if _, err := DecryptPKCS1v15WithPublicKey(&key.PublicKey, pkcs1CiphertextFromEM(key, emTrailingSep)); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected short message error")
	}
}

func TestDecryptOAEPWithPublicKey(t *testing.T) {
	key := mustKey(t, 1024)
	msg := []byte("oaep plaintext")
	cipher, _ := oaepCiphertext(t, key, sha256.New(), msg)
	plain, err := DecryptOAEPWithPublicKey(sha256.New(), &key.PublicKey, cipher)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatalf("unexpected plaintext")
	}
}

func TestDecryptOAEPWithPublicKeyErrors(t *testing.T) {
	key := mustKey(t, 1024)
	smallPub := &rsa.PublicKey{N: big.NewInt(257), E: 3}
	k := key.PublicKey.Size()
	h := sha256.New()

	if _, err := DecryptOAEPWithPublicKey(h, nil, nil); err == nil {
		t.Fatalf("expected nil pub error")
	}

	if _, err := DecryptOAEPWithPublicKey(h, &rsa.PublicKey{}, nil); err == nil {
		t.Fatalf("expected invalid pub error")
	}

	if _, err := DecryptOAEPWithPublicKey(nil, &key.PublicKey, nil); err == nil {
		t.Fatalf("expected nil hash error")
	}

	if _, err := DecryptOAEPWithPublicKey(h, &key.PublicKey, []byte{1, 2, 3}); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected length error")
	}

	nBytes := key.N.Bytes()
	if len(nBytes) < k {
		pad := make([]byte, k)
		copy(pad[k-len(nBytes):], nBytes)
		nBytes = pad
	}
	if _, err := DecryptOAEPWithPublicKey(h, &key.PublicKey, nBytes); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected modulus compare error")
	}

	shortCipher := make([]byte, smallPub.Size())
	if _, err := DecryptOAEPWithPublicKey(h, smallPub, shortCipher); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected em length error")
	}

	emBadFirst := make([]byte, k)
	emBadFirst[0] = 0x01
	badCipher := pkcs1CiphertextFromEM(key, emBadFirst)
	if _, err := DecryptOAEPWithPublicKey(h, &key.PublicKey, badCipher); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected leading byte error")
	}

	msg := []byte("oaep failure")
	db, seed := oaepDB(t, h, k, msg)
	db[0] ^= 0x01
	badLHash := oaepCiphertextFromDB(key, h, db, seed)
	if _, err := DecryptOAEPWithPublicKey(h, &key.PublicKey, badLHash); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected lhash error")
	}

	h.Reset()
	lHash := h.Sum(nil)
	dbNoSep := make([]byte, k-h.Size()-1)
	copy(dbNoSep[:len(lHash)], lHash)
	seedNoSep := make([]byte, h.Size())
	if _, err := rand.Read(seedNoSep); err != nil {
		t.Fatalf("seed: %v", err)
	}
	badSep := oaepCiphertextFromDB(key, h, dbNoSep, seedNoSep)
	if _, err := DecryptOAEPWithPublicKey(h, &key.PublicKey, badSep); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected separator missing error")
	}

	dbBadPadding, seedBadPadding := oaepDB(t, h, k, msg)
	dbBadPadding[h.Size()] = 0x02
	badPadding := oaepCiphertextFromDB(key, h, dbBadPadding, seedBadPadding)
	if _, err := DecryptOAEPWithPublicKey(h, &key.PublicKey, badPadding); !errors.Is(err, rsa.ErrDecryption) {
		t.Fatalf("expected padding error")
	}
}

func TestSignPKCS1v15WithPublicKey(t *testing.T) {
	key := mustKey(t, 1024)
	msg := []byte("public sign")
	digest := sha256.Sum256(msg)

	if _, err := SignPKCS1v15WithPublicKey(nil, crypto.SHA256, digest[:]); err == nil {
		t.Fatalf("expected nil pub error")
	}

	if _, err := SignPKCS1v15WithPublicKey(&rsa.PublicKey{}, crypto.SHA256, digest[:]); err == nil {
		t.Fatalf("expected invalid pub error")
	}

	if _, err := SignPKCS1v15WithPublicKey(&key.PublicKey, crypto.SHA256, []byte{1, 2, 3}); err == nil {
		t.Fatalf("expected hashed size error")
	}

	blakeDigest := make([]byte, crypto.BLAKE2b_256.Size())
	if _, err := SignPKCS1v15WithPublicKey(&key.PublicKey, crypto.BLAKE2b_256, blakeDigest); err == nil {
		t.Fatalf("expected unsupported hash error")
	}

	smallKey := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 80), E: 65537}
	sha512Digest := sha512.Sum512(msg)
	if _, err := SignPKCS1v15WithPublicKey(smallKey, crypto.SHA512, sha512Digest[:]); !errors.Is(err, rsa.ErrMessageTooLong) {
		t.Fatalf("expected message too long")
	}

	negMod := &rsa.PublicKey{N: new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 256)), E: 3}
	if _, err := SignPKCS1v15WithPublicKey(negMod, crypto.Hash(0), []byte{1, 2, 3}); !errors.Is(err, rsa.ErrMessageTooLong) {
		t.Fatalf("expected modulus compare error")
	}

	sig, err := SignPKCS1v15WithPublicKey(&key.PublicKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	em := new(big.Int).Exp(new(big.Int).SetBytes(sig), key.D, key.N).Bytes()
	expectedLen := key.PublicKey.Size()
	if len(em) < expectedLen {
		padded := make([]byte, expectedLen)
		copy(padded[expectedLen-len(em):], em)
		em = padded
	}
	if em[1] != 0x01 {
		t.Fatalf("missing block type")
	}
	if !bytes.Contains(em, digest[:]) {
		t.Fatalf("digest not embedded")
	}
}

func TestSignPKCS1v15WithPublicKeySmallPaddingWindow(t *testing.T) {
	pub := &rsa.PublicKey{N: new(big.Int).SetBit(new(big.Int), 15, 1), E: 3}

	// Force psLen calculation to underflow and hit the padding guard branch.
	huge := make([]byte, 1)
	largeLen := int(^uint(0)>>1) - 5
	if largeLen+11 >= 0 {
		t.Fatalf("expected overflow for coverage guard")
	}
	huge = unsafe.Slice(unsafe.SliceData(huge), largeLen)

	if _, err := SignPKCS1v15WithPublicKey(pub, crypto.Hash(0), huge); !errors.Is(err, rsa.ErrMessageTooLong) {
		t.Fatalf("expected padding too short error, got %v", err)
	}
}

func TestSignPSSWithPublicKey(t *testing.T) {
	key := mustKey(t, 1024)
	digest := sha256.Sum256([]byte("pss"))

	if _, err := SignPSSWithPublicKey(rand.Reader, nil, crypto.SHA256, digest[:]); err == nil {
		t.Fatalf("expected nil pub error")
	}

	if _, err := SignPSSWithPublicKey(rand.Reader, &rsa.PublicKey{}, crypto.SHA256, digest[:]); err == nil {
		t.Fatalf("expected invalid pub error")
	}

	if _, err := SignPSSWithPublicKey(rand.Reader, &key.PublicKey, crypto.Hash(0), digest[:]); err == nil {
		t.Fatalf("expected unsupported hash error")
	}

	smallKey := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 80), E: 65537}
	if _, err := SignPSSWithPublicKey(rand.Reader, smallKey, crypto.SHA512, digest[:]); !errors.Is(err, rsa.ErrMessageTooLong) {
		t.Fatalf("expected message too long")
	}

	if _, err := SignPSSWithPublicKey(failingReader{err: errSaltFailure}, &key.PublicKey, crypto.SHA256, digest[:]); !errors.Is(err, errSaltFailure) {
		t.Fatalf("expected salt read error")
	}

	if _, err := SignPSSWithPublicKey(rand.Reader, &key.PublicKey, crypto.SHA256, []byte{1}); err == nil {
		t.Fatalf("expected emsa encode error")
	}

	shortMod := &rsa.PublicKey{N: new(big.Int).SetBit(new(big.Int), 272, 1), E: 65537}
	if sig, err := SignPSSWithPublicKey(rand.Reader, shortMod, crypto.SHA256, digest[:]); err != nil {
		t.Fatalf("sign pss small mod: %v", err)
	} else if len(sig) != shortMod.Size() {
		t.Fatalf("unexpected signature size")
	}

	negMod := &rsa.PublicKey{N: new(big.Int).Neg(new(big.Int).SetBit(new(big.Int), 512, 1)), E: 65537}
	if _, err := SignPSSWithPublicKey(rand.Reader, negMod, crypto.SHA256, digest[:]); !errors.Is(err, rsa.ErrMessageTooLong) {
		t.Fatalf("expected modulus compare error")
	}

	sig, err := SignPSSWithPublicKey(rand.Reader, &key.PublicKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign pss: %v", err)
	}

	dec := new(big.Int).Exp(new(big.Int).SetBytes(sig), key.D, key.N)
	if dec.Sign() == 0 {
		t.Fatalf("expected non-zero encoded message")
	}
}

func TestSignPSSWithPublicKeyEncodeError(t *testing.T) {
	key := mustKey(t, 1024)
	hashID := crypto.SHA3_256

	crypto.RegisterHash(hashID, func() hash.Hash { return fixedSizeHash{size: 1} })
	t.Cleanup(func() {
		crypto.RegisterHash(hashID, sha3.New256)
	})

	digest := make([]byte, hashID.Size())
	if _, err := SignPSSWithPublicKey(rand.Reader, &key.PublicKey, hashID, digest); err == nil || err.Error() != "input must be hashed with given hash" {
		t.Fatalf("expected emsa encode mismatch, got %v", err)
	}
}

func TestMGF1XOR(t *testing.T) {
	h := sha1.New()
	out := bytes.Repeat([]byte{0x00}, h.Size()*2+3)
	seed := []byte("seed")
	mgf1(out, h, seed)
	if bytes.Equal(out, bytes.Repeat([]byte{0x00}, len(out))) {
		t.Fatalf("mask not applied")
	}

	mgf1(out, h, seed)
	if !bytes.Equal(out, bytes.Repeat([]byte{0x00}, len(out))) {
		t.Fatalf("mgf1XOR not reversible")
	}
}

func TestEqualBytes(t *testing.T) {
	if equalBytes([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Fatalf("expected mismatch")
	}
	if equalBytes([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Fatalf("expected length mismatch")
	}
	if !equalBytes([]byte{4, 5, 6}, []byte{4, 5, 6}) {
		t.Fatalf("expected match")
	}
}

func TestEmsaPSSEncode(t *testing.T) {
	hashFunc := sha256.New()
	mHash := hashFunc.Sum(nil)
	salt := []byte{1, 2, 3, 4}
	if _, err := emsaPSSEncode([]byte{1, 2, 3}, 64, salt, hashFunc); err == nil {
		t.Fatalf("expected hash size error")
	}

	if _, err := emsaPSSEncode(mHash, 8, salt, hashFunc); !errors.Is(err, rsa.ErrMessageTooLong) {
		t.Fatalf("expected message too long")
	}

	emBits := 2048 - 1
	encoded, err := emsaPSSEncode(mHash, emBits, salt, hashFunc)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded[len(encoded)-1] != 0xbc {
		t.Fatalf("missing trailer field")
	}
}
