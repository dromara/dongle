---
title: SM2 Elliptic Curve Asymmetric Encryption
head:
  - - meta
    - name: description
      content: SM2 asymmetric encryption algorithm, a Chinese national cryptographic standard developed by the State Cryptography Administration, based on elliptic curve cryptography, supports C1C3C2 and C1C2C3 ciphertext orders, uses public key encryption and private key decryption, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encrypt, decrypt, SM2, asymmetric encryption, public key encryption, private key decryption, Chinese cryptography, elliptic curve, C1C3C2, C1C2C3, PKCS8, SPKI
---

# SM2

SM2 is an elliptic curve public key cryptographic algorithm (GM/T 0003-2012) established by China's State Cryptography Administration, and is one of the core algorithms of China's commercial cryptography standards. `dongle` supports standard and streaming `SM2` encryption, providing various ciphertext formats and performance optimization options.

Supported ciphertext formats:

- **C1C3C2**: Recommended format by Chinese cryptographic standards (default), ciphertext structure is `0x04 || C1(64 bytes) || C3(32 bytes) || C2(ciphertext data)`
  - C1: Elliptic curve point (randomly generated)
  - C3: SM3 message digest (for integrity verification)
  - C2: Encrypted data
- **C1C2C3**: Legacy standard compatible format, ciphertext structure is `0x04 || C1(64 bytes) || C2(ciphertext data) || C3(32 bytes)`

Supported performance optimization options:

- **Window size**: Controls the pre-computation window for elliptic curve operations (2-6), default is 4
  - Larger windows provide faster encryption, but with slightly higher memory usage
  - Recommended to use default value 4 or 5 for optimal performance

Notes:

- **Key format**: Uses `PKCS#8` format for private keys, `SPKI/PKIX` format for public keys
- **Ciphertext order**: Encryption and decryption must use the same ciphertext order (C1C3C2 or C1C2C3)
- **Data security**: SM2 provides 256-bit security strength, equivalent to RSA 3072 bits
- **Interoperability**: When interoperating with libraries such as OpenSSL, the same ciphertext order must be explicitly specified
- **Private key security**: Private keys must be properly secured and not leaked
- **Standards compliance**: Fully compliant with GM/T 0003.4-2012 (encryption algorithm) and GM/T 0003.5-2012 (curve parameters)

Import required modules:
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/keypair"
)
```

## Create Key Pair

```go
kp := keypair.NewSm2KeyPair()
// Set ciphertext order (optional, default is C1C3C2)
kp.SetOrder(keypair.C1C3C2)
// Set window size (optional, default is 4, range 2-6)
kp.SetWindow(4)
```

### Generate Key Pair

```go
// Generate SM2 key pair (256-bit elliptic curve)
err := kp.GenKeyPair()
if err != nil {
    panic(err)
}

// Get PEM format public key
publicKey := kp.PublicKey  
// Get PEM format private key
privateKey := kp.PrivateKey
```

### Set Key Pair from Existing PEM Format Keys

```go
// Set PEM format public key
kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXy
RHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA==
-----END PUBLIC KEY-----`)

// Set PEM format private key
kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5
u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJE
crAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg
-----END PRIVATE KEY-----`)
```

### Set Key Pair from Existing DER Format Keys

```go
// Set Base64 encoded DER format public key
kp.SetPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXyRHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA=="))

// Set Base64 encoded DER format private key
kp.SetPrivateKey([]byte("MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJEcrAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg"))
```

### Format `DER` Format Keys to `PEM` Format

```go
// Format base64 encoded DER format public key to PEM format
publicKey, err := kp.FormatPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXyRHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA=="))

// Format base64 encoded DER format private key to PEM format
privateKey, err := kp.FormatPrivateKey([]byte("MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJEcrAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg"))
```

### Compress `PEM` Format Keys to `DER` Format

```go
// Compress PEM format public key to base64 encoded DER format (remove PEM format public key's header/footer and line breaks)
publicKey, err := kp.CompressPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXy
RHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA==
-----END PUBLIC KEY-----`))

// Compress PEM format private key to base64 encoded DER format (remove PEM format private key's header/footer and line breaks)
privateKey, err := kp.CompressPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5
u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJE
crAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg
-----END PRIVATE KEY-----`))
```

## Public Key Encryption

Input data
```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").BySm2(kp)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm2(kp)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm2(kp)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output data
```go
// Output Hex encoded string
hexString := encrypter.ToHexString() // e.g.: 047fae94fd1a8b880d8d5454dd8df30c40...
// Output Hex encoded byte slice
hexBytes := encrypter.ToHexBytes()   // e.g.: []byte("047fae94fd1a8b880d8d5454dd8df30c40...")

// Output Base64 encoded string
base64String := encrypter.ToBase64String() // e.g.: BH+ulP0ai4gNjVRU3Y3zDEA=...
// Output Base64 encoded byte slice
base64Bytes := encrypter.ToBase64Bytes()   // e.g.: []byte("BH+ulP0ai4gNjVRU3Y3zDEA=...")

// Output raw unencoded string
rawString := encrypter.ToRawString()
// Output raw unencoded byte slice
rawBytes := encrypter.ToRawBytes()  
```

## Private Key Decryption

Input data
```go
// Input Hex encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).BySm2(kp)
// Input Hex encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm2(kp)
// Input Hex encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm2(kp)

// Input Base64 encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm2(kp)
// Input Base64 encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm2(kp)
// Input Base64 encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm2(kp)

// Input raw string
decrypter := dongle.Decrypt.FromRawString(rawString).BySm2(kp)
// Input raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm2(kp)
// Input raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm2(kp)

// Check decryption error
if decrypter.Error != nil {
	fmt.Printf("Decryption error: %v\n", decrypter.Error)
	return
}
```

Output data
```go
// Output decrypted string
decrypter.ToString() // hello world
// Output decrypted byte slice
decrypter.ToBytes()  // []byte("hello world")
```