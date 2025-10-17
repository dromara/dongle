---
title: AES Symmetric Encryption Algorithm
head:
  - - meta
    - name: description
      content: AES Encryption Algorithm | A lightweight, semantic and developer-friendly golang encoding & crypto library
  - - meta
    - name: keywords
      content: encryption, decryption, AES, symmetric encryption algorithm, block mode, padding mode, CBC, ECB, CTR, GCM, CFB, OFB
---

# AES

AES (Advanced Encryption Standard) is a symmetric encryption algorithm that supports `16-byte`, `24-byte`, and `32-byte` key lengths. `dongle` supports standard and streaming `AES` encryption and provides multiple block modes, padding modes, and output formats.

Supported block modes:

- **CBC（Cipher Block Chaining）**：Cipher Block Chaining mode, requires setting key `Key`, initialization vector `IV` (16 bytes), and padding mode `Padding`
- **ECB（Electronic Codebook）**：Electronic Codebook mode, requires setting key `Key` and padding mode `Padding`
- **CTR（Counter）**：Counter mode, requires setting key `Key` and initialization vector `IV` (12 bytes)
- **GCM（Galois/Counter Mode）**：Galois/Counter mode, requires setting key `Key`, nonce `Nonce` (12 bytes), and additional authenticated data `AAD` (optional)
- **CFB（Cipher Feedback）**：Cipher Feedback mode, requires setting key `Key` and initialization vector `IV` (16 bytes)
- **OFB（Output Feedback）**：Output Feedback mode, requires setting key `Key` and initialization vector `IV` (16 bytes)

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
c := cipher.NewAesCipher(cipher.CBC)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))
// Set padding mode (optional, default is PKCS7, only CBC/ECB block modes need to set padding mode)
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
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// Output Base64 encoded string
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("SMa8B24dopRuHA5Z6cka6Q==")

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
decrypter.ToBytes() // []byte("hello world")
```

## ECB Mode

### Create Cipher

```go
c := cipher.NewAesCipher(cipher.ECB)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set padding mode (optional, defaults to PKCS7, only CBC/ECB block modes require padding mode)
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
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// Output Base64 encoded string
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("SMa8B24dopRuHA5Z6cka6Q==")

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
decrypter.ToBytes() // []byte("hello world")
```

## CTR Mode

### Create Cipher

```go
c := cipher.NewAesCipher(cipher.CTR)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (12 bytes)
c.SetIV([]byte("123456789012"))
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
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// Output Base64 encoded string
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("SMa8B24dopRuHA5Z6cka6Q==")

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
// Set nonce (12 bytes)
c.SetNonce([]byte("123456789012"))
// Set additional authenticated data (optional)
c.SetAAD([]byte("additional data"))
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
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// Output Base64 encoded string
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("SMa8B24dopRuHA5Z6cka6Q==")

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
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// Output Base64 encoded string
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("SMa8B24dopRuHA5Z6cka6Q==")

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
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// Output Base64 encoded string
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("SMa8B24dopRuHA5Z6cka6Q==")

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


