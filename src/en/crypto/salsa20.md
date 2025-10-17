---
title: Salsa20 Stream Cipher Encryption Algorithm
head:
  - - meta
    - name: description
      content: Salsa20 encryption algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: encryption, decryption, Salsa20, symmetric encryption algorithm, stream cipher
---

# Salsa20

Salsa20 is a modern high-performance stream cipher algorithm that uses a fixed-length `32`-byte key and `8`-byte nonce to encrypt and decrypt data. `dongle` supports standard and streaming `Salsa20` encryption with multiple input formats, output formats, and streaming capabilities.

Salsa20 is a symmetric encryption algorithm that uses the same key for encryption and decryption. As a stream cipher, Salsa20 can handle data of arbitrary length without alignment requirements.

## Notes

- **Key Length**: Salsa20 key must be `32` bytes
- **Nonce Length**: Salsa20 nonce must be `8` bytes
- **Data Length**: Supports arbitrary length data with no alignment requirements
- **Nonce Uniqueness**: Each nonce under a key must be unique and cannot be reused
- **Security**: Salsa20 provides high security and is widely used in modern cryptographic applications

Import related modules:
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Create Cipher

```go
c := cipher.NewSalsa20Cipher()
// Set key (must be 32 bytes)
c.SetKey([]byte("dongle1234567890abcdef123456789x"))
// Set nonce (must be 8 bytes)
c.SetNonce([]byte("12345678"))
```

## Encrypt Data

### Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").BySalsa20(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySalsa20(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySalsa20(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded string
hexString := encrypter.ToHexString() // 4a1c8f2d3e5a6b7c
// Output Hex encoded byte slice
hexBytes := encrypter.ToHexBytes()   // []byte("4a1c8f2d3e5a6b7c")

// Output Base64 encoded string
base64String := encrypter.ToBase64String() // ShyPLT5aa3w=
// Output Base64 encoded byte slice
base64Bytes := encrypter.ToBase64Bytes()   // []byte("ShyPLT5aa3w=")

// Output unencoded raw string
rawString := encrypter.ToRawString()
// Output unencoded raw byte slice
rawBytes := encrypter.ToRawBytes()
```

## Decrypt Data

### Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).BySalsa20(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySalsa20(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySalsa20(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).BySalsa20(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySalsa20(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySalsa20(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).BySalsa20(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySalsa20(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).BySalsa20(c)

// Check decryption error
if decrypter.Error != nil {
	fmt.Printf("Decryption error: %v\n", decrypter.Error)
	return
}
```

### Output Data

```go
// Output decrypted string
decrypter.ToString() // hello world
// Output decrypted byte slice
decrypter.ToBytes()  // []byte("hello world")
```
