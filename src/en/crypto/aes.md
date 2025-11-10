---
title: AES Symmetric Encryption Algorithm
head:
  - - meta
    - name: description
      content: AES (Advanced Encryption Standard) symmetric encryption algorithm, supports 16, 24 or 32 byte keys, provides multiple block modes (CBC, ECB, CTR, GCM, CFB, OFB) and padding modes, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encryption, decryption, AES, symmetric encryption algorithm, block mode, padding mode, CBC, ECB, CTR, GCM, CFB, OFB
---

# AES

AES (Advanced Encryption Standard) is a symmetric encryption algorithm that supports `16-byte`, `24-byte`, and `32-byte` key lengths. `dongle` supports standard and streaming `AES` encryption and provides multiple block modes, padding modes, and output formats.

Supported block modes:

- **CBC (Cipher Block Chaining)**: Cipher Block Chaining mode, requires setting key `Key`, initialization vector `IV` (16 bytes), and padding mode `Padding`
- **ECB (Electronic Codebook)**: Electronic Codebook mode, requires setting key `Key` and padding mode `Padding`
- **CTR (Counter)**: Counter mode, requires setting key `Key` and initialization vector `IV` (16 bytes)
- **GCM (Galois/Counter Mode)**: Galois/Counter mode, requires setting key `Key`, nonce `Nonce` (1-255 bytes), and additional authenticated data `AAD` (optional)
- **CFB (Cipher Feedback)**: Cipher Feedback mode, requires setting key `Key` and initialization vector `IV` (16 bytes)
- **OFB (Output Feedback)**: Output Feedback mode, requires setting key `Key` and initialization vector `IV` (16 bytes)

Supported padding modes:

- **No**: No padding, plaintext length must be a multiple of 16
- **Zero**: Zero padding, fills with zero bytes to block boundary, if plaintext length is not a multiple of 16, fills with 0x00 bytes
- **PKCS7**: PKCS#7 padding, most commonly used padding method, fills with N bytes of value N, where N is the number of padding bytes
- **PKCS5**: PKCS#5 padding, suitable for 8-byte block size, fills with N bytes of value N, where N is the number of padding bytes
- **AnsiX923**: ANSI X.923 padding, fills with 0x00 except the last byte, the last byte indicates the number of padding bytes
- **ISO97971**: ISO/IEC 9797-1 padding, first byte is 0x80, rest filled with 0x00
- **ISO10126**: ISO/IEC 10126 padding, fills with random bytes except the last byte, the last byte indicates the number of padding bytes
- **ISO78164**: ISO/IEC 7816-4 padding, first byte is 0x80, rest filled with 0x00
- **Bit**: Bit padding, adds a 1 bit at the end of plaintext, then fills with 0 bits to block boundary
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
c := cipher.NewAesCipher(cipher.CBC)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))
// Set padding mode
c.SetPadding(cipher.PKCS7)
```

### Encrypt Data

 Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

 Output Data

```go
// Output Hex encoded string
encrypter.ToHexString() // b0a72d41c2a05fc42c98fe49ad0cead7
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("b0a72d41c2a05fc42c98fe49ad0cead7")

// Output Base64 encoded string
encrypter.ToBase64String() // sKctQcKgX8QsmP5JrQzq1w==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("sKctQcKgX8QsmP5JrQzq1w==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

 Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Input hex-encoded file
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Input base64-encoded ciphertext file
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// Input unencoded raw file
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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
c := cipher.NewAesCipher(cipher.ECB)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set padding mode
c.SetPadding(cipher.PKCS7)
```

### Encrypt Data

 Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

 Output Data

```go
// Output Hex encoded string
encrypter.ToHexString() // b32102513a0675ddb7ca7b8b4b26abce
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("b32102513a0675ddb7ca7b8b4b26abce")

// Output Base64 encoded string
encrypter.ToBase64String() // syECUToGdd23ynuLSyarzg==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("syECUToGdd23ynuLSyarzg==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

 Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Input hex-encoded file
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Input base64-encoded ciphertext file
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// Input unencoded raw file
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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
c := cipher.NewAesCipher(cipher.CTR)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))      
```

### Encrypt Data

 Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

 Output Data

```go
// Output Hex encoded string
encrypter.ToHexString() // d081959747c6a9a357665b
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("d081959747c6a9a357665b")

// Output Base64 encoded string
encrypter.ToBase64String() // 0IGVl0fGqaNXZls=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("0IGVl0fGqaNXZls=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

 Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Input hex-encoded file
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Input base64-encoded ciphertext file
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// Input unencoded raw file
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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

GCM mode provides authenticated encryption functionality and supports additional authenticated data (AAD).

### Create Cipher

```go
c := cipher.NewAesCipher(cipher.GCM)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set nonce (1-255 bytes)
c.SetNonce([]byte("1234567890"))
// Set additional authenticated data (optional)
c.SetAAD([]byte("dongle")) 
```

### Encrypt Data

 Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

 Output Data

```go
// Output Hex encoded string
encrypter.ToHexString() // 0ffef48b9154a7234cc04e373f86198a8ed7b27f054ad7886c677b
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("0ffef48b9154a7234cc04e373f86198a8ed7b27f054ad7886c677b")

// Output Base64 encoded string
encrypter.ToBase64String() // D/70i5FUpyNMwE43P4YZio7Xsn8FStcIbGd7
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("D/70i5FUpyNMwE43P4YZio7Xsn8FStcIbGd7")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

 Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Input hex-encoded file
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Input base64-encoded ciphertext file
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// Input unencoded raw file
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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

> **Note**: CFB mode uses CFB8 implementation. For the first 16 bytes of data, CFB8 and OFB modes will produce the same encryption results. This is a feature of Go's standard library CFB8 implementation, not an error.

### Create Cipher

```go
c := cipher.NewAesCipher(cipher.CFB)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))  
```

### Encrypt Data

 Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

 Output Data

```go
// Output Hex encoded string
encrypter.ToHexString() // d081959747c6a9a357665b
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("d081959747c6a9a357665b")

// Output Base64 encoded string
encrypter.ToBase64String() // 0IGVl0fGqaNXZls=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("0IGVl0fGqaNXZls=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

 Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Input hex-encoded file
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Input base64-encoded file
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// Input unencoded raw file
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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
c := cipher.NewAesCipher(cipher.OFB)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))  
```

### Encrypt Data

 Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

 Output Data

```go
// Output Hex encoded string
encrypter.ToHexString() // d081959747c6a9a357665b
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("d081959747c6a9a357665b")

// Output Base64 encoded string
encrypter.ToBase64String() // 0IGVl0fGqaNXZls=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("0IGVl0fGqaNXZls=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

 Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Input hex-encoded file
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Input base64-encoded ciphertext file
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// Input unencoded raw file
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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


