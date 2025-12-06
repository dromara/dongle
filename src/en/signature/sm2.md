---
title: SM2 Digital Signature Algorithm
head:
  - - meta
    - name: description
      content: SM2 digital signature algorithm, a Chinese national cryptographic standard developed by the State Cryptography Administration, based on elliptic curve cryptography, uses private key for signing and public key for verification, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, sign, verify, SM2, digital signature algorithm, asymmetric encryption, elliptic curve, private key signing, public key verification, Chinese cryptography, PKCS8, SPKI, UID, SM3
---

# SM2

SM2 is an elliptic curve public key cryptographic algorithm (GM/T 0003-2012) established by China's State Cryptography Administration, and is one of the core algorithms of China's commercial cryptography standards. `dongle` supports standard and streaming `SM2` digital signatures, providing signature and verification functions compliant with GM/T 0009-2012 standard.

SM2 signature algorithm features:

- **Chinese Cryptographic Standard**: Fully compliant with GM/T 0009-2012 digital signature standard
- **High Security**: Uses 256-bit elliptic curve, providing security strength equivalent to RSA 3072 bits
- **User Identifier**: Supports custom UID (User Identifier), default is `"1234567812345678"`
- **Hash Algorithm**: Built-in SM3 hash algorithm for message digest
- **Signature Format**: Uses ASN.1 DER format to store signatures (standard format)
- **Performance Optimization**: Supports window size optimization to improve signature and verification performance

Notes:

- **Key format**: Uses `PKCS#8` format for private keys, `SPKI/PKIX` format for public keys
- **UID Consistency**: Signing and verification must use the same UID, otherwise verification will fail
- **Default UID**: If UID is not set, the default value `"1234567812345678"` will be used (compliant with GM/T 0009-2012)
- **Private key security**: Private keys must be properly secured and not leaked. Only the private key holder can generate valid signatures
- **Signature verification**: Anyone can use the public key to verify the validity of signatures
- **Standards compliance**: Fully compliant with GM/T 0009-2012 (Digital Signature Algorithm) standard

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
// Set user identifier UID (optional, default is "1234567812345678")
kp.SetUID([]byte("user@example.com"))
// Set window size (optional, default is 4, range 2-6, for performance optimization)
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

## Private Key Signing

### Input Data

```go
// Input string
signer := dongle.Sign.FromString("hello world").BySm2(kp)
// Input byte slice
signer := dongle.Sign.FromBytes([]byte("hello world")).BySm2(kp)
// Input file stream
file, _ := os.Open("test.txt")
signer := dongle.Sign.FromFile(file).BySm2(kp)

// Check signing error
if signer.Error != nil {
	fmt.Printf("Signing error: %v\n", signer.Error)
	return
}
```

### Output Data

```go
// Output Hex encoded signature string
hexString := signer.ToHexString() // e.g.: 3045022100a1b2c3d4e5f6...
// Output Hex encoded signature byte slice
hexBytes := signer.ToHexBytes()   // e.g.: []byte("3045022100a1b2c3d4e5f6...")

// Output Base64 encoded signature string
base64String := signer.ToBase64String() // e.g.: MEUCIQCobLPeVv...
// Output Base64 encoded signature byte slice
base64Bytes := signer.ToBase64Bytes()   // e.g.: []byte("MEUCIQCobLPeVv...")

// Output raw unencoded signature string
rawString := signer.ToRawString()
// Output raw unencoded signature byte slice
rawBytes := signer.ToRawBytes()
```

## Public Key Verification

> Note: The `WithXxxSign` method must be called before `BySm2`

### Input Data

```go
// Input string
verifier := dongle.Verify.FromString("hello world")
// Input byte slice
verifier := dongle.Verify.FromBytes([]byte("hello world"))
// Input file stream
file, _ := os.Open("test.txt")
verifier := dongle.Verify.FromFile(file)

// Set Hex encoded signature
verifier.WithHexSign(hexBytes).BySm2(kp)
// Set Base64 encoded signature
verifier.WithBase64Sign(base64Bytes).BySm2(kp)
// Set raw unencoded signature
verifier.WithRawSign(rawBytes).BySm2(kp)

// Check verification error
if verifier.Error != nil {
    fmt.Printf("Verification error: %v\n", verifier.Error)
    return
}
```

### Output Data

```go
// Output verification result
verifier.ToBool() // true or false
```
