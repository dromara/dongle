---
title: RC4 Stream Cipher Encryption Algorithm
head:
  - - meta
    - name: description
      content: RC4 (Rivest Cipher 4) stream cipher encryption algorithm, supports 1-256 byte variable-length keys, can process data of any length without padding, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encryption, decryption, RC4, Rivest Cipher 4, symmetric encryption algorithm, stream cipher
---

# RC4

RC4 (Rivest Cipher 4) is a stream cipher encryption algorithm that uses variable-length keys (1-256 bytes) to encrypt and decrypt data. `dongle` supports standard and streaming `RC4` encryption and provides multiple input formats, output formats, and streaming processing capabilities.

RC4 is a symmetric encryption algorithm that uses the same key for encryption and decryption. Since RC4 is a stream cipher, it does not require padding and can directly process data of any length.

Import related modules:
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Create Cipher

```go
c := cipher.NewRc4Cipher()
// Set key (1-256 bytes)
c.SetKey([]byte("dongle"))
```

## Encrypt Data

Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByRc4(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByRc4(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByRc4(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data

```go
// Output Hex encoded string
hexString := encrypter.ToHexString() // eba154b4cb5a9038dbbf9d
// Output hex-encoded byte slice
hexBytes := encrypter.ToHexBytes()   // []byte("eba154b4cb5a9038dbbf9d")

// Output Base64 encoded string
base64String := encrypter.ToBase64String() // 66FUtMtakDjbv50=
// Output base64-encoded byte slice
base64Bytes := encrypter.ToBase64Bytes()   // []byte("66FUtMtakDjbv50=")

// Output unencoded raw string
rawString := encrypter.ToRawString()
// Output unencoded raw byte slice
rawBytes := encrypter.ToRawBytes()
```

## Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByRc4(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByRc4(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByRc4(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByRc4(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByRc4(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByRc4(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByRc4(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByRc4(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByRc4(c)

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
