---
title: Twofish Symmetric Encryption Algorithm
head:
  - - meta
    - name: description
      content: Twofish symmetric encryption algorithm, supports 16, 24, or 32-byte keys, provides multiple block modes (CBC, ECB, CTR, GCM, CFB, OFB) and padding modes, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encryption, decryption, Twofish, symmetric encryption algorithm, block mode, padding mode, CBC, ECB, CTR, GCM, CFB, OFB
---

# Twofish

Twofish is a symmetric encryption algorithm that supports fixed-length keys with key sizes of `16`, `24`, or `32` bytes. `dongle` supports standard and streaming `Twofish` encryption with multiple block modes, padding modes, and output formats.

The following block modes are supported:

- **CBC (Cipher Block Chaining)**: Requires setting key `Key`, initialization vector `IV` (16 bytes), and padding mode `Padding`
- **ECB (Electronic Codebook)**: Requires setting key `Key` and padding mode `Padding`
- **CTR (Counter)**: Requires setting key `Key` and initialization vector `IV` (16 bytes)
- **CFB (Cipher Feedback)**: Requires setting key `Key` and initialization vector `IV` (16 bytes)
- **OFB (Output Feedback)**: Requires setting key `Key` and initialization vector `IV` (16 bytes)
- **GCM (Galois/Counter Mode)**: Requires setting key `Key`, nonce `Nonce` (1-255 bytes), and optional additional authenticated data `AAD`

The following padding modes are supported:

- **No**: No padding, plaintext length must be a multiple of 16
- **Zero**: Zero padding, pad with zero bytes to block boundary, if plaintext length is not a multiple of 16, pad with 0x00 bytes
- **PKCS7**: PKCS#7 padding, the most commonly used padding method, pad with N bytes of value N, where N is the number of padding bytes
- **PKCS5**: PKCS#5 padding, suitable for 16-byte block size, pad with N bytes of value N, where N is the number of padding bytes
- **AnsiX923**: ANSI X.923 padding, pad with 0x00 except for the last byte, the last byte indicates the number of padding bytes
- **ISO97971**: ISO/IEC 9797-1 padding, first byte is 0x80, rest padded with 0x00
- **ISO10126**: ISO/IEC 10126 padding, pad with random bytes except for the last byte, the last byte indicates the number of padding bytes
- **ISO78164**: ISO/IEC 7816-4 padding, first byte is 0x80, rest padded with 0x00
- **Bit**: Bit padding, add a 1 bit at the end of plaintext, then pad with 0 bits to block boundary
- **TBC**: Trailing Bit Complement padding, determines padding bytes based on the most significant bit of the last data byte (MSB=0 uses 0x00, MSB=1 uses 0xFF)

> **Note**: Only `CBC/ECB` block modes require padding mode, only `CBC/CTR/CFB/OFB` block modes require initialization vector

Import the required modules:
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## CBC Mode

### Create Cipher
```go
c := cipher.NewTwofishCipher(cipher.CBC)
// Set key (16, 24, or 32 bytes)
c.SetKey([]byte("1234567890123456"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))
// Set padding mode
c.SetPadding(cipher.PKCS7)
```

### Encrypt Data

Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data

```go
// Output Hex encoded string
encrypter.ToHexString() // 778e2e1e61afba198bb5128017cb4b81
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("778e2e1e61afba198bb5128017cb4b81")

// Output Base64 encoded string
encrypter.ToBase64String() // d44uHmGvuhmLtRKAF8tLgQ==
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("d44uHmGvuhmLtRKAF8tLgQ==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

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
c := cipher.NewTwofishCipher(cipher.ECB)
// Set key (16, 24, or 32 bytes)
c.SetKey([]byte("1234567890123456"))
// Set padding mode
c.SetPadding(cipher.PKCS7)
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 0fb94e36c8a2f1c2f66994638121d2c8
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("0fb94e36c8a2f1c2f66994638121d2c8")

// Output Base64 encoded string
encrypter.ToBase64String() // D7lONsii8cL2aZRjgSHSyA==
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("D7lONsii8cL2aZRjgSHSyA==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

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
c := cipher.NewTwofishCipher(cipher.CTR)
// Set key (16, 24, or 32 bytes)
c.SetKey([]byte("1234567890123456"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 7cd470bfd6d8e18b57d269
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("7cd470bfd6d8e18b57d269")

// Output Base64 encoded string
encrypter.ToBase64String() // fNRwv9bY4YtX0mk=
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("fNRwv9bY4YtX0mk=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)

// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)

// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

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
c := cipher.NewTwofishCipher(cipher.CFB)
// Set key (16, 24, or 32 bytes)
c.SetKey([]byte("1234567890123456"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 7cd470bfd6d8e18b57d269
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("7cd470bfd6d8e18b57d269")

// Output Base64 encoded string
encrypter.ToBase64String() // fNRwv9bY4YtX0mk=
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("fNRwv9bY4YtX0mk=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

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
c := cipher.NewTwofishCipher(cipher.OFB)
// Set key (16, 24, or 32 bytes)
c.SetKey([]byte("1234567890123456"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 7cd470bfd6d8e18b57d269
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("7cd470bfd6d8e18b57d269")

// Output Base64 encoded string
encrypter.ToBase64String() // fNRwv9bY4YtX0mk=
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("fNRwv9bY4YtX0mk=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

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

## GCM Mode

### Create Cipher

```go
c := cipher.NewTwofishCipher(cipher.GCM)
// Set key (16, 24, or 32 bytes)
c.SetKey([]byte("1234567890123456"))
// Set nonce (1-255 bytes)
c.SetNonce([]byte("12345678"))
// Set additional authenticated data (optional)
c.SetAAD([]byte("dongle"))
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 36059dc3fbbc82418a032f74ae9ffa55077aa925f61a1a16eb0dd0
// Output Hex encoded byte slice
encrypter.ToHexBytes()  // []byte("36059dc3fbbc82418a032f74ae9ffa55077aa925f61a1a16eb0dd0")

// Output Base64 encoded string
encrypter.ToBase64String() // NgWdw/u8gkGKAy90rp/6VQd6qSX2GhoW6w3Q
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()  // []byte("NgWdw/u8gkGKAy90rp/6VQd6qSX2GhoW6w3Q")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

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