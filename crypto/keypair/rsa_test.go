package keypair

import (
	"crypto"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func genPair(t *testing.T, format RsaKeyFormat) (*RsaKeyPair, []byte, []byte) {
	t.Helper()
	kp := NewRsaKeyPair()
	kp.SetFormat(format)
	if err := kp.GenKeyPair(1024); err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return kp, kp.CompressPublicKey(kp.PublicKey), kp.CompressPrivateKey(kp.PrivateKey)
}

func TestRSA_Setters(t *testing.T) {
	kp := NewRsaKeyPair()
	assert.Equal(t, PKCS8, kp.Format)
	assert.Equal(t, crypto.SHA256, kp.Hash)

	kp.SetFormat(PKCS1)
	kp.SetPadding(OAEP)
	kp.SetHash(crypto.SHA512)
	kp.SetType(PrivateKey)

	assert.Equal(t, PKCS1, kp.Format)
	assert.Equal(t, OAEP, kp.Padding)
	assert.Equal(t, crypto.SHA512, kp.Hash)
	assert.Equal(t, PrivateKey, kp.Type)
}

func TestRSA_GenKeyPair(t *testing.T) {
	t.Run("pkcs1", func(t *testing.T) {
		kp, _, _ := genPair(t, PKCS1)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN RSA PUBLIC KEY-----")
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN RSA PRIVATE KEY-----")
	})

	t.Run("pkcs8", func(t *testing.T) {
		kp, _, _ := genPair(t, PKCS8)
		assert.Contains(t, string(kp.PublicKey), "-----BEGIN PUBLIC KEY-----")
		assert.Contains(t, string(kp.PrivateKey), "-----BEGIN PRIVATE KEY-----")
	})

	t.Run("invalid size", func(t *testing.T) {
		kp := NewRsaKeyPair()
		err := kp.GenKeyPair(1)
		assert.Error(t, err)
		assert.Nil(t, kp.PublicKey)
		assert.Nil(t, kp.PrivateKey)
	})

	t.Run("unsupported format", func(t *testing.T) {
		kp := NewRsaKeyPair()
		kp.SetFormat("unknown")
		err := kp.GenKeyPair(1024)
		assert.Error(t, err)
		assert.IsType(t, UnsupportedKeyFormatError{}, err)
	})
}

func TestRSA_FormatAndSetKeys(t *testing.T) {
	kp, pubBody, priBody := genPair(t, PKCS8)

	assert.NotContains(t, string(pubBody), "BEGIN")
	assert.NotContains(t, string(priBody), "BEGIN")
	assert.NotContains(t, string(pubBody), "\n")
	assert.NotContains(t, string(priBody), "\n")

	kp.SetFormat(PKCS1)
	pemPub1, err := kp.FormatPublicKey(pubBody)
	assert.NoError(t, err)
	assert.Contains(t, string(pemPub1), "-----BEGIN RSA PUBLIC KEY-----")

	pemPri1, err := kp.FormatPrivateKey(priBody)
	assert.NoError(t, err)
	assert.Contains(t, string(pemPri1), "-----BEGIN RSA PRIVATE KEY-----")

	kp.SetFormat(PKCS8)
	pemPub2, err := kp.FormatPublicKey(pubBody)
	assert.NoError(t, err)
	assert.Contains(t, string(pemPub2), "-----BEGIN PUBLIC KEY-----")

	pemPri2, err := kp.FormatPrivateKey(priBody)
	assert.NoError(t, err)
	assert.Contains(t, string(pemPri2), "-----BEGIN PRIVATE KEY-----")

	assert.NoError(t, kp.SetPublicKey(pubBody))
	assert.NoError(t, kp.SetPrivateKey(priBody))
	assert.Equal(t, pemPub2, kp.PublicKey)
	assert.Equal(t, pemPri2, kp.PrivateKey)

	_, err = kp.FormatPublicKey(nil)
	assert.IsType(t, EmptyPublicKeyError{}, err)
	_, err = kp.FormatPublicKey([]byte("!!"))
	assert.IsType(t, InvalidPublicKeyError{}, err)

	_, err = kp.FormatPrivateKey(nil)
	assert.IsType(t, EmptyPrivateKeyError{}, err)
	_, err = kp.FormatPrivateKey([]byte("!!"))
	assert.IsType(t, InvalidPrivateKeyError{}, err)

	kp.SetFormat("unknown")
	_, err = kp.FormatPublicKey(pubBody)
	assert.IsType(t, UnsupportedKeyFormatError{}, err)
	_, err = kp.FormatPrivateKey(priBody)
	assert.IsType(t, UnsupportedKeyFormatError{}, err)
}

func TestRSA_ParseKeys(t *testing.T) {
	pkcs1, _, _ := genPair(t, PKCS1)
	pub1, err := pkcs1.ParsePublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pub1)
	pri1, err := pkcs1.ParsePrivateKey()
	assert.NoError(t, err)
	assert.NotNil(t, pri1)

	pkcs8, _, _ := genPair(t, PKCS8)
	pub2, err := pkcs8.ParsePublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pub2)
	pri2, err := pkcs8.ParsePrivateKey()
	assert.NoError(t, err)
	assert.NotNil(t, pri2)

	empty := NewRsaKeyPair()
	_, err = empty.ParsePublicKey()
	assert.IsType(t, EmptyPublicKeyError{}, err)
	_, err = empty.ParsePrivateKey()
	assert.IsType(t, EmptyPrivateKeyError{}, err)

	badPem := NewRsaKeyPair()
	badPem.PublicKey = []byte("invalid")
	badPem.PrivateKey = []byte("invalid")
	_, err = badPem.ParsePublicKey()
	assert.IsType(t, InvalidPublicKeyError{}, err)
	_, err = badPem.ParsePrivateKey()
	assert.IsType(t, InvalidPrivateKeyError{}, err)

	unknown := NewRsaKeyPair()
	unknown.PublicKey = pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN KEY", Bytes: []byte{1, 2, 3}})
	_, err = unknown.ParsePublicKey()
	assert.IsType(t, UnsupportedKeyFormatError{}, err)
	unknown.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	_, err = unknown.ParsePrivateKey()
	assert.IsType(t, UnsupportedKeyFormatError{}, err)

	invalid := NewRsaKeyPair()
	invalid.PublicKey = []byte("-----BEGIN RSA PUBLIC KEY-----\nAA==\n-----END RSA PUBLIC KEY-----\n")
	_, err = invalid.ParsePublicKey()
	assert.IsType(t, InvalidPublicKeyError{}, err)

	invalid.PublicKey = []byte("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n")
	_, err = invalid.ParsePublicKey()
	assert.IsType(t, InvalidPublicKeyError{}, err)

	invalid.PrivateKey = []byte("-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n")
	_, err = invalid.ParsePrivateKey()
	assert.IsType(t, InvalidPrivateKeyError{}, err)

	invalid.PrivateKey = []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")
	_, err = invalid.ParsePrivateKey()
	assert.IsType(t, InvalidPrivateKeyError{}, err)
}
