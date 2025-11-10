---
title: SM4 Symmetric Encryption Algorithm
head:
  - - meta
    - name: description
      content: SM4 symmetric encryption algorithm, a commercial symmetric block cipher published by the Chinese National Cryptography Administration, supports 16-byte keys, provides multiple block modes (CBC, ECB, CTR, GCM, CFB, OFB) and padding modes, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encryption, decryption, SM4, symmetric encryption algorithm, Chinese national cryptography algorithm, block mode, padding mode, CBC, ECB, CTR, GCM, CFB, OFB
---

# SM4

`SM4` is a symmetric encryption algorithm, a commercial symmetric block cipher algorithm published by the Chinese National Cryptography Administration, that supports a `16`-byte key length. `dongle` supports both standard and streaming `SM4` encryption, providing multiple block modes, padding modes, and output formats.

The following block modes are supported:

- **CBC (Cipher Block Chaining)**: Cipher block chaining mode, requires setting the key `Key`, initialization vector `IV` (16 bytes), and padding mode `Padding`
- **ECB (Electronic Codebook)**: Electronic codebook mode, requires setting the key `Key` and padding mode `Padding`
- **CTR (Counter)**: Counter mode, requires setting the key `Key` and initialization vector `IV` (16 bytes)
- **GCM (Galois/Counter Mode)**: Galois/Counter mode, requires setting the key `Key`, nonce `Nonce` (1-255 bytes), and additional authenticated data `AAD` (optional)
- **CFB (Cipher Feedback)**: Cipher feedback mode, requires setting the key `Key` and initialization vector `IV` (16 bytes)
- **OFB (Output Feedback)**: Output feedback mode, requires setting the key `Key` and initialization vector `IV` (16 bytes)

The following padding modes are supported:

- **No**: No padding, plaintext length must be a multiple of 16
- **Zero**: Zero padding, pad with zero bytes to block boundary, if plaintext length is not a multiple of 16, pad with 0x00 bytes
- **PKCS7**: PKCS#7 padding, the most commonly used padding method, pad with N bytes of value N, where N is the number of padding bytes
- **PKCS5**: PKCS#5 padding, suitable for 8-byte block size, pad with N bytes of value N, where N is the number of padding bytes
- **AnsiX923**: ANSI X.923 padding, all bytes except the last one are padded with 0x00, the last byte indicates the number of padding bytes
- **ISO97971**: ISO/IEC 9797-1 padding, the first byte is 0x80, the rest are padded with 0x00
- **ISO10126**: ISO/IEC 10126 padding, all bytes except the last one are padded with random bytes, the last byte indicates the number of padding bytes
- **ISO78164**: ISO/IEC 7816-4 padding, the first byte is 0x80, the rest are padded with 0x00
- **Bit**: Bit padding, add a 1 bit at the end of the plaintext, then pad with 0 bits to the block boundary
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
c := cipher.NewSm4Cipher(cipher.CBC)
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
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// Check encryption error
if encrypter.Error != nil {
    fmt.Printf("Encryption error: %v\n", encrypter.Error)
    return
}
```

 Output Data

```go
// Output Hex encoded string
encrypter.ToHexString() // 6cdb55b749358b9fba993fa7c545fce6
// Output Hex encoded byte slice
encrypter.ToHexBytes()   // []byte("6cdb55b749358b9fba993fa7c545fce6")

// Output Base64 encoded string
encrypter.ToBase64String() // bNtVt0k1i5+6mT+nxUX85g==
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()   // []byte("bNtVt0k1i5+6mT+nxUX85g==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

 Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Input Hex encoded file
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

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
c := cipher.NewSm4Cipher(cipher.ECB)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set padding mode
c.SetPadding(cipher.PKCS7) 
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// Check encryption error
if encrypter.Error != nil {
    fmt.Printf("Encryption error: %v\n", encrypter.Error)
    return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 0eb581f0836f423e088fe68ab8011a2b
// Output Hex encoded byte slice
encrypter.ToHexBytes()   // []byte("0eb581f0836f423e088fe68ab8011a2b")

// Output Base64 encoded string
encrypter.ToBase64String() // DrWB8INvQj4Ij+aKuAEaKw==
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()   // []byte("DrWB8INvQj4Ij+aKuAEaKw==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data
```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

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
c := cipher.NewSm4Cipher(cipher.CTR)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))      
```

### Encrypt Data

 Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// Check encryption error
if encrypter.Error != nil {
    fmt.Printf("Encryption error: %v\n", encrypter.Error)
    return
}
```

 Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 274288a7eac8bb982cb53f
// Output Hex encoded byte slice
encrypter.ToHexBytes()   // []byte("274288a7eac8bb982cb53f")

// Output Base64 encoded string
encrypter.ToBase64String() // J0KIp+rIu5gstT8=
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()   // []byte("J0KIp+rIu5gstT8=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

 Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// Check decryption error
if decrypter.Error != nil {
    fmt.Printf("Decryption error: %v\n", decrypter.Error)
    return
}
```

 Output Data

```go
// Output string
decrypter.ToString() // hello world
// Output byte slice
decrypter.ToBytes()  // []byte("hello world")
```

## GCM Mode

GCM mode provides authenticated encryption functionality and supports additional authenticated data (AAD).

### Create Cipher

```go
c := cipher.NewSm4Cipher(cipher.GCM)
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
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// Check encryption error
if encrypter.Error != nil {
    fmt.Printf("Encryption error: %v\n", encrypter.Error)
    return
}
```

 Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 248e07df909c174df7ba9ba48e32f8f1ba3f9e1b3344ad8981b50d
// Output Hex encoded byte slice
encrypter.ToHexBytes()   // []byte("248e07df909c174df7ba9ba48e32f8f1ba3f9e1b3344ad8981b50d")

// Output Base64 encoded string
encrypter.ToBase64String() // JI4H35CcF033upukjjL48bo/nhszRK2JgbUN
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()   // []byte("JI4H35CcF033upukjjL48bo/nhszRK2JgbUN")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

 Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// Check decryption error
if decrypter.Error != nil {
    fmt.Printf("Decryption error: %v\n", decrypter.Error)
    return
}
```

 Output Data
```go
// Output string
decrypter.ToString() // hello world
// Output byte slice
decrypter.ToBytes()  // []byte("hello world")
```

## CFB Mode

> **Note**: CFB mode uses CFB8 implementation. For the first 16 bytes of data, CFB8 and OFB modes will produce the same encryption result. This is a feature of the Go standard library CFB8 implementation, not a bug.

### Create Cipher

```go
c := cipher.NewSm4Cipher(cipher.CFB)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))  
```

### Encrypt Data

 Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// Check encryption error
if encrypter.Error != nil {
    fmt.Printf("Encryption error: %v\n", encrypter.Error)
    return
}
```

 Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 274288a7eac8bb982cb53f
// Output Hex encoded byte slice
encrypter.ToHexBytes()   // []byte("274288a7eac8bb982cb53f")

// Output Base64 encoded string
encrypter.ToBase64String() // J0KIp+rIu5gstT8=
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()   // []byte("J0KIp+rIu5gstT8=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

 Input Data
```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// Check decryption error
if decrypter.Error != nil {
    fmt.Printf("Decryption error: %v\n", decrypter.Error)
    return
}
```

 Output Data
```go
// Output string
decrypter.ToString() // hello world
// Output byte slice
decrypter.ToBytes()  // []byte("hello world")
```

## OFB Mode

> **Note**: CFB mode uses CFB8 implementation. For the first 16 bytes of data, CFB8 and OFB modes will produce the same encryption result. This is a feature of the Go standard library CFB8 implementation, not a bug.

### Create Cipher

```go
c := cipher.NewSm4Cipher(cipher.OFB)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))  
```

### Encrypt Data

 Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// Check encryption error
if encrypter.Error != nil {
    fmt.Printf("Encryption error: %v\n", encrypter.Error)
    return
}
```

 Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 274288a7eac8bb982cb53f
// Output Hex encoded byte slice
encrypter.ToHexBytes()   // []byte("274288a7eac8bb982cb53f")

// Output Base64 encoded string
encrypter.ToBase64String() // J0KIp+rIu5gstT8=
// Output Base64 encoded byte slice
encrypter.ToBase64Bytes()   // []byte("J0KIp+rIu5gstT8=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

 Input Data

```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// Check decryption error
if decrypter.Error != nil {
    fmt.Printf("Decryption error: %v\n", decrypter.Error)
    return
}
```

 Output Data
```go
// Output string
decrypter.ToString() // hello world
// Output byte slice
decrypter.ToBytes()  // []byte("hello world")
```