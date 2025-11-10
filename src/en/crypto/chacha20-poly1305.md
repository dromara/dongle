---
title: ChaCha20-Poly1305 Authenticated Encryption Algorithm
head:
  - - meta
    - name: description
      content: ChaCha20-Poly1305 authenticated encryption algorithm (AEAD), supports 32-byte keys and 12-byte nonce, supports Additional Authenticated Data (AAD), can process data of any length without padding, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encryption, decryption, ChaCha20-Poly1305, ChaCha20, Poly1305, symmetric encryption algorithm, stream cipher, message authentication code, authenticated encryption, AEAD
---

# ChaCha20-Poly1305

ChaCha20-Poly1305 is a modern high-performance authenticated encryption algorithm (AEAD) that combines `ChaCha20` stream cipher and `Poly1305` message authentication code. It uses fixed-length `32` byte keys and `12` byte nonces to encrypt and authenticate data. `dongle` supports standard and streaming `ChaCha20-Poly1305` encryption, providing multiple input formats, output formats and streaming processing capabilities.

ChaCha20-Poly1305 is a symmetric encryption algorithm that uses the same key for encryption and decryption. As an `AEAD` algorithm, it not only provides confidentiality protection, but also provides integrity and authenticity verification, capable of detecting data tampering.

Important Notes

- **Key Length**: ChaCha20-Poly1305 key must be `32` bytes
- **Nonce Length**: ChaCha20-Poly1305 nonce must be `12` bytes
- **Additional Data**: Optional additional authenticated data (AAD), used for verification but not encryption
- **Authentication Tag**: Encrypted data contains `16` bytes of authentication tag
- **Nonce Uniqueness**: Nonce must be unique under each key and cannot be reused
- **Security**: ChaCha20-Poly1305 provides high security and is widely adopted by standards such as `TLS1.3`

Import related modules:
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Create Cipher

```go
c := cipher.NewChaCha20Poly1305Cipher()
// Set key (must be 32 bytes)
c.SetKey([]byte("dongle1234567890abcdef123456789x"))
// Set nonce (must be 12 bytes)
c.SetNonce([]byte("123456789012"))
// Set additional authenticated data (optional)
c.SetAAD([]byte("dongle"))
```

## Encrypt Data

Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByChaCha20Poly1305(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByChaCha20Poly1305(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByChaCha20Poly1305(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data

```go
// Output Hex encoded string
hexString := encrypter.ToHexString() // 04457bd9e26e18b1975a89ed76e38bbddc6364721923967b10ca4c
// Output hex-encoded byte slice
hexBytes := encrypter.ToHexBytes()   // []byte("04457bd9e26e18b1975a89ed76e38bbddc6364721923967b10ca4c")

// Output Base64 encoded string
base64String := encrypter.ToBase64String() // BEV72eJuGLGXWontduOLvdxjZHIZI5Z7EMpM
// Output base64-encoded byte slice
base64Bytes := encrypter.ToBase64Bytes()   // []byte("BEV72eJuGLGXWontduOLvdxjZHIZI5Z7EMpM")

// Output unencoded raw string
rawString := encrypter.ToRawString()
// Output unencoded raw byte slice
rawBytes := encrypter.ToRawBytes()
```

## Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByChaCha20Poly1305(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByChaCha20Poly1305(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByChaCha20Poly1305(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByChaCha20Poly1305(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByChaCha20Poly1305(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByChaCha20Poly1305(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByChaCha20Poly1305(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByChaCha20Poly1305(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).ByChaCha20Poly1305(c)

// Check decryption error
if decrypter.Error != nil {
	fmt.Printf("Decryption error: %v\n", decrypter.Error)
	return
}
```

Output Data

```go
// Output decrypted string
decrypter.ToString() // hello world
// Output decrypted byte slice
decrypter.ToBytes()  // []byte("hello world")
```