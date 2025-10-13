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
c := cipher.NewTeaCipher(cipher.CBC)
// Set key (must be 16 bytes)
c.SetKey([]byte("dongle1234567890"))
// Set initialization vector (8 bytes)
c.SetIV([]byte("87654321"))
// Set padding mode (optional, default is PKCS7, only CBC/ECB block modes need to set padding mode)
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
// Output hex-encoded string
encrypter.ToHexString() // a97fc8fdda9bebc7
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("a97fc8fdda9bebc7")

// Output base64-encoded string
encrypter.ToBase64String() // qX/I/dqb68c=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("qX/I/dqb68c=")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
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
// Set padding mode (optional, default is PKCS7, only CBC/ECB block modes need to set padding mode)
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
// Output hex-encoded string
encrypter.ToHexString() // a97fc8fdda9bebc7
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("a97fc8fdda9bebc7")

// Output base64-encoded string
encrypter.ToBase64String() // qX/I/dqb68c=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("qX/I/dqb68c=")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
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
decrypter.ToString() // hello world
// Output decrypted byte slice
decrypter.ToBytes() // []byte("hello world")
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
// Output hex-encoded string
encrypter.ToHexString() // a97fc8fdda9bebc7
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("a97fc8fdda9bebc7")

// Output base64-encoded string
encrypter.ToBase64String() // qX/I/dqb68c=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("qX/I/dqb68c=")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
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
// Output string
decrypter.ToString() // hello world
// Output byte slice
decrypter.ToBytes()  // []byte("hello world")
```

## CFB Mode

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
// Output hex-encoded string
encrypter.ToHexString() // a97fc8fdda9bebc7
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("a97fc8fdda9bebc7")

// Output base64-encoded string
encrypter.ToBase64String() // qX/I/dqb68c=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("qX/I/dqb68c=")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
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
// Output string
decrypter.ToString() // hello world
// Output byte slice
decrypter.ToBytes() // []byte("hello world")
```

## OFB Mode

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
// Output hex-encoded string
encrypter.ToHexString() // a97fc8fdda9bebc7
// Output hex-encoded byte slice
encrypter.ToHexBytes()   // []byte("a97fc8fdda9bebc7")

// Output base64-encoded string
encrypter.ToBase64String() // qX/I/dqb68c=
// Output base64-encoded byte slice
encrypter.ToBase64Bytes()   // []byte("qX/I/dqb68c=")

// Output raw string
encrypter.ToRawString()
// Output raw byte slice
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
// Output string
decrypter.ToString() // hello world
// Output byte slice
decrypter.ToBytes() // []byte("hello world")
```