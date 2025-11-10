---
title: TEA Symmetric Encryption Algorithm
head:
  - - meta
    - name: description
      content: TEA (Tiny Encryption Algorithm) symmetric encryption algorithm, supports 16-byte keys, provides multiple block modes (CBC, ECB, CTR, CFB, OFB) and padding modes, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encryption, decryption, TEA, Tiny Encryption Algorithm, symmetric encryption algorithm, block mode, padding mode, CBC, ECB, CTR, CFB, OFB
---

# TEA

TEA (Tiny Encryption Algorithm) is a simple and efficient block cipher algorithm that uses a fixed-length `16-byte` key to encrypt and decrypt data. `dongle` supports standard and streaming `TEA` encryption and provides multiple block modes, padding modes, and output formats.

Supported block modes:

- **CBC (Cipher Block Chaining)**: Cipher block chaining mode, requires setting key `Key`, initialization vector `IV` (8 bytes), and padding mode `Padding`
- **ECB (Electronic Codebook)**: Electronic codebook mode, requires setting key `Key` and padding mode `Padding`
- **CTR (Counter)**: Counter mode, requires setting key `Key` and initialization vector `IV` (8 bytes)
- **CFB (Cipher Feedback)**: Cipher feedback mode, requires setting key `Key` and initialization vector `IV` (8 bytes)
- **OFB (Output Feedback)**: Output feedback mode, requires setting key `Key` and initialization vector `IV` (8 bytes)

> **Note**: The TEA algorithm does not support `GCM` (Galois/Counter Mode) mode. This is because `GCM` mode requires the cipher algorithm to have a `128-bit` block size, while `TEA` only has a `64-bit` block size (`8` bytes). This is a technical limitation of cryptographic standards, not an implementation issue.

Supported padding modes:

- **No**: No padding, plaintext length must be a multiple of 8
- **Zero**: Zero padding, pad with zero bytes to block boundary, if plaintext length is not a multiple of 8, pad with 0x00 bytes
- **PKCS7**: PKCS#7 padding, the most commonly used padding method, pad with N bytes of value N, where N is the number of padding bytes
- **PKCS5**: PKCS#5 padding, suitable for 8-byte block size, pad with N bytes of value N, where N is the number of padding bytes
- **AnsiX923**: ANSI X.923 padding, pad with 0x00 except for the last byte, the last byte indicates the number of padding bytes
- **ISO97971**: ISO/IEC 9797-1 padding, first byte is 0x80, rest padded with 0x00
- **ISO10126**: ISO/IEC 10126 padding, pad with random bytes except for the last byte, the last byte indicates the number of padding bytes
- **ISO78164**: ISO/IEC 7816-4 padding, first byte is 0x80, rest padded with 0x00
- **Bit**: Bit padding, add a 1-bit at the end of plaintext, then pad with 0-bits to block boundary
- **TBC**: Trailing Bit Complement padding, determines padding bytes based on the most significant bit of the last data byte (MSB=0 uses 0x00, MSB=1 uses 0xFF)

> **Note**: Only `CBC/ECB` block modes require padding mode, only `CBC/CTR/CFB/OFB` block modes require initialization vector

Import related modules:
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## CBC Mode

### Create Cipher
```go
c := cipher.NewTeaCipher(cipher.CBC)
// Set key (must be 16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))
// Set padding mode
c.SetPadding(cipher.PKCS7)
// Set rounds (optional, default 64 rounds)
c.SetRounds(64)
```

### Encrypt Data

Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
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
// Output Hex encoded string
encrypter.ToHexString() // a97fc8fdda9bebc7
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("a97fc8fdda9bebc7")

// Output Base64 encoded string
encrypter.ToBase64String() // qX/I/dqb68c=
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("qX/I/dqb68c=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

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

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// Input unencoded raw file stream
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
decrypter.ToString() // hello world
// Output decrypted byte slice
decrypter.ToBytes()  // []byte("hello world")
```

## ECB Mode

### Create Cipher

```go
c := cipher.NewTeaCipher(cipher.ECB)
// Set key (must be 16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set padding mode
c.SetPadding(cipher.PKCS7)
// Set rounds (optional, default 64 rounds)
c.SetRounds(64)
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
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
// Output Hex encoded string
encrypter.ToHexString() // 2b4e8f1a5c7d9e3f6a8b2c4d5e7f9a1b
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("2b4e8f1a5c7d9e3f6a8b2c4d5e7f9a1b")

// Output Base64 encoded string
encrypter.ToBase64String() // K06PGsdfnj+aqyzUXn+aGw==
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("K06PGsdfnj+aqyzUXn+aGw==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

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

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)

// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)

// Input unencoded raw file stream
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
decrypter.ToString() // hello world
// Output decrypted byte slice
decrypter.ToBytes()  // []byte("hello world")
```

## CTR Mode

### Create Cipher

```go
c := cipher.NewTeaCipher(cipher.CTR)
// Set key (must be 16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))
// Set rounds (optional, default 64 rounds)
c.SetRounds(64)
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
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
// Output Hex encoded string
encrypter.ToHexString() // 7f3a9b2e4d6c8f1a5e7b9c3d4f6a8b2e
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("7f3a9b2e4d6c8f1a5e7b9c3d4f6a8b2e")

// Output Base64 encoded string
encrypter.ToBase64String() // fzqbLk1sjxpeec09T2qLLg==
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("fzqbLk1sjxpeec09T2qLLg==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

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

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// Input unencoded raw file stream
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
decrypter.ToString() // hello world
// Output decrypted byte slice
decrypter.ToBytes()  // []byte("hello world")
```

## CFB Mode

> **Note**: CFB mode uses CFB8 implementation. For the first 16 bytes of data, CFB8 and OFB modes will produce the same encryption result. This is a feature of the Go standard library CFB8 implementation, not a bug.

### Create Cipher

```go
c := cipher.NewTeaCipher(cipher.CFB)
// Set key (must be 16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))
// Set rounds (optional, default 64 rounds)
c.SetRounds(64)
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
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
// Output Hex encoded string
encrypter.ToHexString() // 5a8c3f1e7b4d9a2c6e8f1b5d3a7c9e2f
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("5a8c3f1e7b4d9a2c6e8f1b5d3a7c9e2f")

// Output Base64 encoded string
encrypter.ToBase64String() // WowPHntNmi5ujxtaPHyf
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("WowPHntNmi5ujxtaPHyf")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

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

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// Input unencoded raw file stream
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
decrypter.ToString() // hello world
// Output decrypted byte slice
decrypter.ToBytes()  // []byte("hello world")
```

## OFB Mode

> **Note**: CFB mode uses CFB8 implementation. For the first 16 bytes of data, CFB8 and OFB modes will produce the same encryption result. This is a feature of the Go standard library CFB8 implementation, not a bug.

### Create Cipher

```go
c := cipher.NewTeaCipher(cipher.OFB)
// Set key (must be 16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))
// Set rounds (optional, default 64 rounds)
c.SetRounds(64)
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
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
// Output Hex encoded string
encrypter.ToHexString() // 3f7a9c2e5d8b1f4a6e9c3d7b2f5a8e1c
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("3f7a9c2e5d8b1f4a6e9c3d7b2f5a8e1c")

// Output Base64 encoded string
encrypter.ToBase64String() // P3qcLl2LH0puPD17L1qOHA==
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("P3qcLl2LH0puPD17L1qOHA==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

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

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// Input unencoded raw file stream
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
decrypter.ToString() // hello world
// Output decrypted byte slice
decrypter.ToBytes()  // []byte("hello world")
```