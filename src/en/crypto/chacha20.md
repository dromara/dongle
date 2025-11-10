---
title: ChaCha20 Stream Cipher Encryption Algorithm
head:
  - - meta
    - name: description
      content: ChaCha20 stream cipher encryption algorithm, supports 32-byte keys and 12-byte nonce, can process data of any length without padding, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encryption, decryption, ChaCha20, symmetric encryption algorithm, stream cipher, nonce, streaming processing, Hex, Base64
---

# ChaCha20

ChaCha20 is a modern high-performance stream cipher algorithm that uses a fixed-length `32` bytes key and `12` bytes nonce to encrypt and decrypt data. `dongle` supports standard and streaming `ChaCha20` encryption, providing multiple input formats, output formats, and streaming processing capabilities.

ChaCha20 is a symmetric encryption algorithm that uses the same key for both encryption and decryption. ChaCha20 as a stream cipher can handle data of any length without data alignment requirements.

 Notes

- **Key Length**: ChaCha20 key must be `32` bytes
- **Nonce Length**: ChaCha20 nonce must be `12` bytes
- **Data Length**: Supports data of any length, no alignment requirements
- **Nonce Uniqueness**: The nonce must be unique for each key and cannot be reused
- **Security**: ChaCha20 provides high security and is widely used in modern encryption applications

Import related modules:
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Create Cipher

```go
c := cipher.NewChaCha20Cipher()
// Set key (must be 32 bytes)
c.SetKey([]byte("dongle1234567890abcdef123456789x"))
// Set nonce (must be 12 bytes)
c.SetNonce([]byte("123456789012"))
```

## Encrypt Data

 Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByChaCha20(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByChaCha20(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByChaCha20(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

 Output Data

```go
// Output Hex encoded string
hexString := encrypter.ToHexString() // cd010dae3bbf72faa75abf
// Output hex-encoded byte slice
hexBytes := encrypter.ToHexBytes()   // []byte("cd010dae3bbf72faa75abf")

// Output Base64 encoded string
base64String := encrypter.ToBase64String() // zQENrju/cvqnWr8=
// Output base64-encoded byte slice
base64Bytes := encrypter.ToBase64Bytes()   // []byte("zQENrju/cvqnWr8=")

// Output unencoded raw string
rawString := encrypter.ToRawString()
// Output unencoded raw byte slice
rawBytes := encrypter.ToRawBytes()
```

## Decrypt Data

 Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByChaCha20(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByChaCha20(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByChaCha20(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByChaCha20(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByChaCha20(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByChaCha20(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByChaCha20(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByChaCha20(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).ByChaCha20(c)

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