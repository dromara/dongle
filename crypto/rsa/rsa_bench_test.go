package rsa

import (
	"bytes"
	"crypto"
	"io"
	"sync"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
)

var (
	benchOnce      sync.Once
	benchPrepErr   error
	benchPKCS1     *keypair.RsaKeyPair
	benchPKCS8     *keypair.RsaKeyPair
	benchPlaintext = []byte("hello rsa bench")
	benchCipherP1  []byte
	benchCipherO   []byte
	benchSigP1     []byte
	benchSigPSS    []byte
)

func prepareBenchData(b *testing.B) {
	b.Helper()
	benchOnce.Do(func() {
		benchPrepErr = initBenchData()
	})
	if benchPrepErr != nil {
		b.Fatal(benchPrepErr)
	}
}

func initBenchData() error {
	benchPKCS1 = keypair.NewRsaKeyPair()
	benchPKCS1.SetFormat(keypair.PKCS1)
	benchPKCS1.SetHash(crypto.SHA256)
	if err := benchPKCS1.GenKeyPair(1024); err != nil {
		return err
	}

	benchPKCS8 = keypair.NewRsaKeyPair()
	benchPKCS8.SetFormat(keypair.PKCS8)
	benchPKCS8.SetHash(crypto.SHA256)
	if err := benchPKCS8.GenKeyPair(1024); err != nil {
		return err
	}

	// Precompute ciphertext/signatures for decryption/verification benches
	var err error
	benchCipherP1, err = NewStdEncrypter(benchPKCS1).Encrypt(benchPlaintext)
	if err != nil {
		return err
	}

	benchCipherO, err = NewStdEncrypter(benchPKCS8).Encrypt(benchPlaintext)
	if err != nil {
		return err
	}

	pri := *benchPKCS1
	pri.SetType(keypair.PrivateKey)
	benchSigP1, err = NewStdSigner(&pri).Sign(benchPlaintext)
	if err != nil {
		return err
	}

	priPSS := *benchPKCS8
	priPSS.SetType(keypair.PrivateKey)
	benchSigPSS, err = NewStdSigner(&priPSS).Sign(benchPlaintext)
	if err != nil {
		return err
	}

	return nil
}

func BenchmarkStdEncryptPKCS1v15(b *testing.B) {
	prepareBenchData(b)
	enc := NewStdEncrypter(benchPKCS1)
	if enc.Error != nil {
		b.Fatalf("init encrypter: %v", enc.Error)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := enc.Encrypt(benchPlaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdEncryptOAEP(b *testing.B) {
	prepareBenchData(b)
	enc := NewStdEncrypter(benchPKCS8)
	if enc.Error != nil {
		b.Fatalf("init encrypter: %v", enc.Error)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := enc.Encrypt(benchPlaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdDecryptPKCS1v15(b *testing.B) {
	prepareBenchData(b)
	kp := *benchPKCS1
	kp.SetType(keypair.PrivateKey)
	dec := NewStdDecrypter(&kp)
	if dec.Error != nil {
		b.Fatalf("init decrypter: %v", dec.Error)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := dec.Decrypt(benchCipherP1); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdDecryptOAEP(b *testing.B) {
	prepareBenchData(b)
	kp := *benchPKCS8
	kp.SetType(keypair.PrivateKey)
	dec := NewStdDecrypter(&kp)
	if dec.Error != nil {
		b.Fatalf("init decrypter: %v", dec.Error)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := dec.Decrypt(benchCipherO); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdSignPKCS1v15(b *testing.B) {
	prepareBenchData(b)
	kp := *benchPKCS1
	kp.SetType(keypair.PrivateKey)
	signer := NewStdSigner(&kp)
	if signer.Error != nil {
		b.Fatalf("init signer: %v", signer.Error)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := signer.Sign(benchPlaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdSignPSS(b *testing.B) {
	prepareBenchData(b)
	kp := *benchPKCS8
	kp.SetType(keypair.PrivateKey)
	signer := NewStdSigner(&kp)
	if signer.Error != nil {
		b.Fatalf("init signer: %v", signer.Error)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := signer.Sign(benchPlaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdVerifyPKCS1v15(b *testing.B) {
	prepareBenchData(b)
	verifier := NewStdVerifier(benchPKCS1)
	if verifier.Error != nil {
		b.Fatalf("init verifier: %v", verifier.Error)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.Verify(benchPlaintext, benchSigP1); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStdVerifyPSS(b *testing.B) {
	prepareBenchData(b)
	verifier := NewStdVerifier(benchPKCS8)
	if verifier.Error != nil {
		b.Fatalf("init verifier: %v", verifier.Error)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.Verify(benchPlaintext, benchSigPSS); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamEncrypt(b *testing.B) {
	prepareBenchData(b)
	data := bytes.Repeat(benchPlaintext, 2)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer(nil)
		se := NewStreamEncrypter(buf, benchPKCS1).(*StreamEncrypter)
		if se.Error != nil {
			b.Fatalf("init stream encrypter: %v", se.Error)
		}
		if _, err := se.Write(data); err != nil {
			b.Fatal(err)
		}
		if err := se.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamDecrypt(b *testing.B) {
	prepareBenchData(b)
	// Use ciphertext produced by stream encryption once
	buf := bytes.NewBuffer(nil)
	se := NewStreamEncrypter(buf, benchPKCS1).(*StreamEncrypter)
	if se.Error != nil {
		b.Fatalf("init stream encrypter: %v", se.Error)
	}
	if _, err := se.Write(bytes.Repeat(benchPlaintext, 2)); err != nil {
		b.Fatalf("prep stream cipher: %v", err)
	}
	if err := se.Close(); err != nil {
		b.Fatalf("prep stream cipher close: %v", err)
	}
	cipher := buf.Bytes()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		kp := *benchPKCS1
		kp.SetType(keypair.PrivateKey)
		reader := bytes.NewReader(cipher)
		sd := NewStreamDecrypter(reader, &kp).(*StreamDecrypter)
		if sd.Error != nil {
			b.Fatalf("init stream decrypter: %v", sd.Error)
		}
		buf := make([]byte, len(cipher))
		for {
			if _, err := sd.Read(buf); err != nil {
				if err == io.EOF {
					break
				}
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkStreamSign(b *testing.B) {
	prepareBenchData(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer(nil)
		kp := *benchPKCS1
		kp.SetType(keypair.PrivateKey)
		ss := NewStreamSigner(buf, &kp).(*StreamSigner)
		if ss.Error != nil {
			b.Fatalf("init stream signer: %v", ss.Error)
		}
		if _, err := ss.Write(benchPlaintext); err != nil {
			b.Fatal(err)
		}
		if err := ss.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamVerify(b *testing.B) {
	prepareBenchData(b)
	// Prepare signature once
	buf := bytes.NewBuffer(nil)
	kp := *benchPKCS1
	kp.SetType(keypair.PrivateKey)
	ss := NewStreamSigner(buf, &kp).(*StreamSigner)
	if ss.Error != nil {
		b.Fatalf("prep signer: %v", ss.Error)
	}
	if _, err := ss.Write(benchPlaintext); err != nil {
		b.Fatalf("prep signer write: %v", err)
	}
	if err := ss.Close(); err != nil {
		b.Fatalf("prep signer close: %v", err)
	}
	sig := buf.Bytes()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(sig)
		sv := NewStreamVerifier(reader, benchPKCS1).(*StreamVerifier)
		if sv.Error != nil {
			b.Fatalf("init stream verifier: %v", sv.Error)
		}
		if _, err := sv.Write(benchPlaintext); err != nil {
			b.Fatal(err)
		}
		if err := sv.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
