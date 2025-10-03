---
head:
  - - meta
    - name: description
      content: DES Encryption Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: des, encryption, decryption, symmetric encryption, block cipher
---

# DES

DES (Data Encryption Standard) is a symmetric encryption algorithm that uses an `8-byte` key. `dongle` supports standard and streaming `DES` encryption and provides multiple block modes, padding modes, and output formats.

Supported block modes:

- **CBC (Cipher Block Chaining)**: Cipher Block Chaining mode, requires setting key `Key`, initialization vector `IV` (8 bytes), and padding mode `Padding`
- **ECB (Electronic Codebook)**: Electronic Codebook mode, requires setting key `Key` and padding mode `Padding`
- **CTR (Counter)**: Counter mode, requires setting key `Key` and initialization vector `IV` (8 bytes)
- **CFB (Cipher Feedback)**: Cipher Feedback mode, requires setting key `Key` and initialization vector `IV` (8 bytes)
- **OFB (Output Feedback)**: Output Feedback mode, requires setting key `Key` and initialization vector `IV` (8 bytes)

> **Note**: DES algorithm does not support `GCM` (Galois/Counter Mode). This is because `GCM` mode requires a cipher algorithm with `128`-bit block size, while `DES` only has `64`-bit block size (`8` bytes). This is a technical limitation of cryptographic standards, not an implementation issue.

Supported padding modes:

- **No**: No padding, plaintext length must be a multiple of 8
- **Zero**: Zero padding, fills with zero bytes to block boundary, if plaintext length is not a multiple of 8, fills with 0x00 bytes
- **PKCS7**: PKCS#7 padding, most commonly used padding method, fills with N bytes of value N, where N is the number of padding bytes
- **PKCS5**: PKCS#5 padding, suitable for 8-byte block size, fills with N bytes of value N, where N is the number of padding bytes
- **AnsiX923**: ANSI X.923 padding, fills with 0x00 except the last byte, the last byte indicates the number of padding bytes
- **ISO97971**: ISO/IEC 9797-1 padding, first byte is 0x80, rest filled with 0x00
- **ISO10126**: ISO/IEC 10126 padding, fills with random bytes except the last byte, the last byte indicates the number of padding bytes
- **ISO78164**: ISO/IEC 7816-4 padding, first byte is 0x80, rest filled with 0x00
- **Bit**: Bit padding, adds a 1 bit at the end of plaintext, then fills with 0 bits to block boundary

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
c := cipher.NewDesCipher(cipher.CBC)
// Set key (8 bytes)
c.SetKey([]byte("12345678"))
// Set padding mode (optional, defaults to PKCS7, only CBC/ECB block modes require padding mode)
c.SetIV([]byte("87654321"))
// Set padding mode (optional, defaults to PKCS7, only CBC/ECB block modes require padding mode)
c.SetIV([]byte("87654321"))
```

### Encrypt Data

Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByDes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByDes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByDes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data

```go
// Output hex-encoded string
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Output base64-encoded string
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByDes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByDes(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByDes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByDes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByDes(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByDes(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByDes(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByDes(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByDes(c)

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
c := cipher.NewDesCipher(cipher.ECB)
// Set key (8 bytes)
c.SetKey([]byte("12345678"))
// Set padding mode (optional, defaults to PKCS7, only CBC/ECB block modes require padding mode)
c.SetPadding(cipher.PKCS7)
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByDes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByDes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByDes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output hex-encoded string
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Output base64-encoded string
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByDes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByDes(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByDes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByDes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByDes(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByDes(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByDes(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByDes(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByDes(c)

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
c := cipher.NewDesCipher(cipher.CTR)
// Set key (8 bytes)
c.SetKey([]byte("12345678"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByDes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByDes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByDes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output hex-encoded string
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Output base64-encoded string
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByDes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByDes(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByDes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByDes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByDes(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByDes(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByDes(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByDes(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByDes(c)

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
decrypter.ToBytes() // []byte("hello world")
```

## CFB Mode

### Create Cipher

```go
c := cipher.NewDesCipher(cipher.CFB)
// Set key (8 bytes)
c.SetKey([]byte("12345678"))
// Set padding mode (optional, defaults to PKCS7, only CBC/ECB block modes require padding mode)
c.SetIV([]byte("87654321"))
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByDes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByDes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByDes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output hex-encoded string
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Output base64-encoded string
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByDes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByDes(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByDes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByDes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByDes(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByDes(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByDes(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByDes(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByDes(c)

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

### Create Cipher

```go
c := cipher.NewDesCipher(cipher.OFB)
// Set key (8 bytes)
c.SetKey([]byte("12345678"))
// Set padding mode (optional, defaults to PKCS7, only CBC/ECB block modes require padding mode)
c.SetIV([]byte("87654321"))
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByDes(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByDes(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByDes(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output hex-encoded string
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Output base64-encoded string
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByDes(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByDes(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByDes(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByDes(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByDes(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByDes(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByDes(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByDes(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByDes(c)

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