---
head:
  - - meta
    - name: description
      content: 3DES Encryption Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: 3des, TripleDES, 3DES, encryption, decryption, symmetric encryption, block cipher
---

# 3DES

3DES (Triple Data Encryption Standard) is a symmetric encryption algorithm that uses a `16-byte` or `24-byte` key. `dongle` supports standard and streaming `3DES` encryption and provides multiple block modes, padding modes, and output formats.

Supported block modes:

- **CBC (Cipher Block Chaining)**: Cipher Block Chaining mode, requires setting key `Key`, initialization vector `IV` (8 bytes), and padding mode `Padding`
- **ECB (Electronic Codebook)**: Electronic Codebook mode, requires setting key `Key` and padding mode `Padding`
- **CTR (Counter)**: Counter mode, requires setting key `Key` and initialization vector `IV` (8 bytes)
- **CFB (Cipher Feedback)**: Cipher Feedback mode, requires setting key `Key` and initialization vector `IV` (8 bytes)
- **OFB (Output Feedback)**: Output Feedback mode, requires setting key `Key` and initialization vector `IV` (8 bytes)

> **Note**: 3DES algorithm does not support `GCM` (Galois/Counter Mode). This is because `GCM` mode requires a cipher algorithm with `128`-bit block size, while `3DES` only has `64`-bit block size (`8` bytes). This is a technical limitation of cryptographic standards, not an implementation issue.

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

> **Note**: Only `CBC/ECB` block modes require padding

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
c := cipher.New3DesCipher(cipher.CBC)
// Set key (16-byte will auto-expand to 24-byte)
c.SetKey([]byte("123456781234567812345678"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))
// Set padding mode (optional, defaults to PKCS7, only CBC/ECB block modes require padding mode)
c.SetPadding(cipher.PKCS7) 
```

### Encrypt Data

Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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
c := cipher.New3DesCipher(cipher.ECB)
// Set key (16-byte will auto-expand to 24-byte)
c.SetKey([]byte("123456781234567812345678"))
// Set padding mode (optional, defaults to PKCS7, only CBC/ECB block modes require padding mode)
c.SetPadding(cipher.PKCS7) 
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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

## CTR Mode

### Create Cipher

```go
c := cipher.New3DesCipher(cipher.CTR)
// Set key (16-byte will auto-expand to 24-byte)
c.SetKey([]byte("123456781234567812345678"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))                   
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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

### Create Cipher

```go
c := cipher.New3DesCipher(cipher.CFB)
// Set key (16-byte will auto-expand to 24-byte)
c.SetKey([]byte("123456781234567812345678"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))                   
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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
c := cipher.New3DesCipher(cipher.OFB)
// Set key (16-byte will auto-expand to 24-byte)
c.SetKey([]byte("123456781234567812345678"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))                  
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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
