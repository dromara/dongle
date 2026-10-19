package sm2

import (
	"math/big"
	"testing"
)

func TestDecryptWithPrivateKeyUnsupportedMode(t *testing.T) {
	privateKey, _ := deterministicKeyPair(t)
	ciphertext := make([]byte, 1+2*32+32)
	ciphertext[0] = 0x04
	if _, err := DecryptWithPrivateKey(privateKey, ciphertext, 0, "unsupported"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSM2CipherFromBytesErrors(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		payload []byte
	}{
		{name: "unsupported mode", mode: "unsupported"},
		{name: "invalid ASN.1 sequence", mode: asn1_c1c2c3, payload: []byte{0x00}},
		{name: "incomplete ASN.1 fields", mode: asn1_c1c2c3, payload: []byte{0x30, 0x01, 0x00}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := sm2CipherFromBytes(test.mode, test.payload, 1); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSM2CipherToBytesUnsupportedMode(t *testing.T) {
	ciphertext := sm2Cipher{keyX: big.NewInt(1), keyY: big.NewInt(2)}
	if _, err := ciphertext.toBytes("unsupported", 1); err == nil {
		t.Fatal("expected error")
	}
}

func TestSM2SignFromBytesErrors(t *testing.T) {
	tests := []struct {
		name string
		mode uint8
		sign []byte
	}{
		{name: "unsupported mode", mode: 2},
		{name: "invalid ASN.1 sequence", mode: sm2SignASN1, sign: []byte{0x00}},
		{name: "incomplete ASN.1 fields", mode: sm2SignASN1, sign: []byte{0x30, 0x01, 0x00}},
		{name: "invalid byte length", mode: sm2SignBytes, sign: []byte{0x01}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := sm2SignFromBytes(test.mode, test.sign, 1); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSM2SignToBytesUnsupportedMode(t *testing.T) {
	signature := sm2Sign{R: big.NewInt(1), S: big.NewInt(2)}
	if _, err := signature.toBytes(2, 1); err == nil {
		t.Fatal("expected error")
	}
}
