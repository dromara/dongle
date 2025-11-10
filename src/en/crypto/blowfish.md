---
title: Blowfish Symmetric Encryption Algorithm
head:
  - - meta
    - name: description
      content: Blowfish symmetric encryption algorithm, supports 1-56 byte variable-length keys, provides multiple block modes (CBC, ECB, CTR, CFB, OFB) and padding modes, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encryption, decryption, Blowfish, symmetric encryption algorithm, block mode, padding mode, CBC, ECB, CTR, CFB, OFB
---

# Blowfish

Blowfish is a symmetric encryption algorithm that supports variable-length keys, with key lengths from `1` to `56` bytes. `dongle` supports standard and streaming `Blowfish` encryption and provides multiple block modes, padding modes, and output formats.

Supported block modes:

- **CBC (Cipher Block Chaining)**: Cipher Block Chaining mode, requires setting key `Key`, initialization vector `IV` (8 bytes), and padding mode `Padding`
- **ECB (Electronic Codebook)**: Electronic Codebook mode, requires setting key `Key` and padding mode `Padding`
- **CTR (Counter)**: Counter mode, requires setting key `Key` and initialization vector `IV` (8 bytes)
- **CFB (Cipher Feedback)**: Cipher Feedback mode, requires setting key `Key` and initialization vector `IV` (8 bytes)
- **OFB (Output Feedback)**: Output Feedback mode, requires setting key `Key` and initialization vector `IV` (8 bytes)

> **Note**: Blowfish algorithm does not support `GCM` (Galois/Counter Mode). This is because `GCM` mode requires a cipher algorithm with `128`-bit block size, while `Blowfish` only has `64`-bit block size (`8` bytes). This is a technical limitation of cryptographic standards, not an implementation issue.

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
c := cipher.NewBlowfishCipher(cipher.CBC)
// Set key (1-56 bytes)
c.SetKey([]byte("12345678"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))
// Set padding mode
c.SetPadding(cipher.PKCS7)
```

### Encrypt Data

Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data

```go
// Output Hex encoded string
encrypter.ToHexString() // f52a4cc3738f6ed0ee8fe4312fa9be82
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("f52a4cc3738f6ed0ee8fe4312fa9be82")

// Output Base64 encoded string
encrypter.ToBase64String() // 9SpMw3OPbtDuj+QxL6m+gg==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("9SpMw3OPbtDuj+QxL6m+gg==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes()
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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
c := cipher.NewBlowfishCipher(cipher.ECB)
// Set key (1-56 bytes)
c.SetKey([]byte("12345678"))
// Set padding mode
c.SetPadding(cipher.PKCS7)
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 77caf7bc47a73ead1497a822dd1a2bf0
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("77caf7bc47a73ead1497a822dd1a2bf0")

// Output Base64 encoded string
encrypter.ToBase64String() // d8r3vEenPq0Ul6gi3Ror8A==
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("d8r3vEenPq0Ul6gi3Ror8A==")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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
c := cipher.NewBlowfishCipher(cipher.CTR)
// Set key (1-56 bytes)
c.SetKey([]byte("12345678"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))                   
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 09f68045da3a38f2620280
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("09f68045da3a38f2620280")

// Output Base64 encoded string
encrypter.ToBase64String() // CfaARdo6OPJiAoA=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("CfaARdo6OPJiAoA=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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
c := cipher.NewBlowfishCipher(cipher.CFB)
// Set key (1-56 bytes)
c.SetKey([]byte("12345678"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))                   
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 09f68045da3a38f217a836
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("09f68045da3a38f217a836")

// Output Base64 encoded string
encrypter.ToBase64String() // CfaARdo6OPIXqDY=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("CfaARdo6OPIXqDY=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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
c := cipher.NewBlowfishCipher(cipher.OFB)
// Set key (1-56 bytes)
c.SetKey([]byte("12345678"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))                  
```

### Encrypt Data

Input Data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data
```go
// Output Hex encoded string
encrypter.ToHexString() // 09f68045da3a38f2613a97
// Output hex-encoded byte slice
encrypter.ToHexBytes()  // []byte("09f68045da3a38f2613a97")

// Output Base64 encoded string
encrypter.ToBase64String() // CfaARdo6OPJhOpc=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()  // []byte("CfaARdo6OPJhOpc=")

// Output unencoded raw string
encrypter.ToRawString()
// Output unencoded raw byte slice
encrypter.ToRawBytes() 
```

### Decrypt Data

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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