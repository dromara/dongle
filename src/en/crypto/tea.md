---
head:
  - - meta
    - name: description
      content: TEA Encryption Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: tea, encryption, decryption, symmetric encryption, block cipher
---

# TEA

TEA (Tiny Encryption Algorithm) is a simple and efficient block cipher algorithm that uses a fixed-length `16-byte` key to encrypt and decrypt data. `dongle` supports standard `TEA` encryption and provides multiple input formats, output formats, and streaming processing capabilities.

TEA is a symmetric encryption algorithm that uses the same key for encryption and decryption. TEA uses `8-byte` data blocks for encryption, and data length must be a multiple of `8`.

Important Notes

- **Key length**: TEA key must be `16` bytes
- **Data length**: Input data length must be a multiple of `8` bytes
- **Round setting**: Supports custom rounds, default is `64` rounds, commonly used also includes `32` rounds
- **Data alignment**: If data length is not a multiple of `8`, manual padding is required
- **Security**: TEA algorithm is relatively simple, suitable for scenarios with high performance requirements but not extremely high security requirements

Import related modules:
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Create Cipher

```go
c := cipher.NewTeaCipher()
// Set key (must be 16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set rounds (optional, default 64 rounds)
c.SetRounds(64)
```

## Encrypt Data

Input Data

```go
// Input string (must be a multiple of 8 bytes)
encrypter := dongle.Encrypt.FromString("12345678").ByTea(c)
// Input byte slice (must be a multiple of 8 bytes)
encrypter := dongle.Encrypt.FromBytes([]byte("12345678")).ByTea(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTea(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data

```go
// Output hex-encoded string
hexString := encrypter.ToHexString() // a97fc8fdda9bebc7
// Output hex-encoded byte slice
hexBytes := encrypter.ToHexBytes()   // []byte("a97fc8fdda9bebc7")

// Output base64-encoded string
base64String := encrypter.ToBase64String() // qX/I/dqb68c=
// Output base64-encoded byte slice
base64Bytes := encrypter.ToBase64Bytes()   // []byte("qX/I/dqb68c=")

// Output raw string
rawString := encrypter.ToRawString()
// Output raw byte slice
rawBytes := encrypter.ToRawBytes()
```

## Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByTea(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTea(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTea(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTea(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTea(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTea(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTea(c)

// Check decryption error
if decrypter.Error != nil {
	fmt.Printf("Decryption error: %v\n", decrypter.Error)
	return
}
```

Output Data

```go
// Output decrypted string
decrypter.ToString() // 12345678
// Output decrypted byte slice
decrypter.ToBytes()  // []byte("12345678")
```
