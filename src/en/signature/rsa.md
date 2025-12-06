---
title: RSA Digital Signature Algorithm
head:
  - - meta
    - name: description
      content: RSA Digital Signature Algorithm, supports PKCS1 and PKCS8 key formats, supports multiple hash algorithms, uses private key for signing and public key for verification, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, signing, verification, RSA, digital signature algorithm, asymmetric encryption, private key signing, public key verification, PKCS1, PKCS8, PSS, PKCS1v15, hash algorithm, Hex, Base64
---

# RSA

RSA digital signature is a digital signature algorithm based on asymmetric encryption, using private key for signing and public key for verification. `dongle` supports standard and streaming `RSA` digital signatures and provides multiple key formats, hash algorithms, and output formats.

Supported key formats:

- **PKCS1**: PKCS#1 format, keys use `-----BEGIN RSA PRIVATE KEY-----` and `-----BEGIN RSA PUBLIC KEY-----` as header and footer
- **PKCS8**: PKCS#8 format, keys use `-----BEGIN PRIVATE KEY-----` and `-----BEGIN PUBLIC KEY-----` as header and footer (recommended)

Supported padding modes:

- **PKCS1v15**: PKCS#1 v1.5 padding mode, can be used for signing/verification, good compatibility
- **PSS**: Probabilistic Signature Scheme, only used for signing/verification, higher security (recommended for signing)

Supported hash algorithms:

- **MD4**: MD4 hash algorithm (not recommended for production use)
- **MD5**: MD5 hash algorithm (not recommended for production use)
- **SHA1**: SHA-1 hash algorithm (not recommended for production use)
- **SHA224**: SHA-224 hash algorithm
- **SHA256**: SHA-256 hash algorithm (recommended)
- **SHA384**: SHA-384 hash algorithm
- **SHA512**: SHA-512 hash algorithm
- **MD5SHA1**: MD5-SHA1 hash algorithm
- **RIPEMD160**: RIPEMD160 hash algorithm
- **SHA3_224**: SHA3_224 hash algorithm
- **SHA3_256**: SHA3_256 hash algorithm
- **SHA3_384**: SHA3_384 hash algorithm
- **SHA3_512**: SHA3_512 hash algorithm
- **SHA512_224**: SHA512_224 hash algorithm
- **SHA512_256**: SHA512_256 hash algorithm
- **BLAKE2s_256**: BLAKE2s_256 hash algorithm
- **BLAKE2b_256**: BLAKE2b_256 hash algorithm
- **BLAKE2b_384**: BLAKE2b_384 hash algorithm
- **BLAKE2b_512**: BLAKE2b_512 hash algorithm

Important Notes:

- **Key length**: It is recommended to use `2048` bits or longer key length to ensure security
- **Key format**: It is recommended to use `PKCS8` format (modern standard)
- **Padding mode**: It is recommended to use `PSS` for signing/verification
- **Hash algorithm**: It is recommended to use `SHA256` or stronger hash algorithms, avoid using `MD5` and `SHA1`
- **Private key security**: Private keys must be properly protected and cannot be leaked, only the private key holder can generate valid signatures
- **Signature verification**: Anyone can use the public key to verify the validity of signatures

Import related modules:
```go
import (
    "crypto"
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/keypair"
)
```

## Create key pair
```go
kp := keypair.NewRsaKeyPair()
// Set key format (optional, default is PKCS8)
kp.SetFormat(keypair.PKCS8)
// Set padding mode (optional, default is empty, PKCS1 format defaults to PKCS1v15, PKCS8 format defaults to PSS)
kp.SetPadding(keypair.PSS)  // or keypair.PKCS1v15
// Set hash algorithm (optional, default is SHA256, used for PSS padding mode)
kp.SetHash(crypto.SHA256)   
```

### Generate key pair

```go
// Generate 2048-bit key pair
err := kp.GenKeyPair(2048)
if err != nil {
    panic(err)
}

// Get public key in PEM format
publicKey := kp.PublicKey  
// Get private key in PEM format
privateKey := kp.PrivateKey
```

### Set key pair from existing PEM format keys

```go
// Set public key in PEM format
kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHq
X1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJ
y4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMez
HC1outlM6x+/BB0BSQIDAQAB
-----END PUBLIC KEY-----`)

// Set private key in PEM format
kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTr
AOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9
a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjh
sg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bE
YA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKs
BL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczv
Idtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7
GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1w
giXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFt
Nts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQ
dHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cuf
PzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaD
a3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxua
RPgUNaDGIh5o
-----END PRIVATE KEY-----`)
```

### Set key pair from existing DER format keys

```go
// Set base64 encoded DER format public key
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// Set base64 encoded DER format private key
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
```

### Format `DER` format keys to `PEM` format

```go
// Format base64 encoded DER format public key to PEM format
publicKey, err := kp.FormatPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))

// Format base64 encoded DER format private key to PEM format
privateKey, err := kp.FormatPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
```

### Compress `PEM` format keys to `DER` format

```go
// Compress PEM format public key to base64 encoded DER format (remove PEM format public key's header/footer and line breaks)
publicKey, err := kp.CompressPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHq
X1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJ
y4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMez
HC1outlM6x+/BB0BSQIDAQAB
-----END PUBLIC KEY-----`))

// Compress PEM format private key to base64 encoded DER format (remove PEM format private key's header/footer and line breaks)
privateKey, err := kp.CompressPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTr
AOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9
a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjh
sg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bE
YA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKs
BL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczv
Idtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7
GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1w
giXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFt
Nts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQ
dHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cuf
PzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaD
a3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxua
RPgUNaDGIh5o
-----END PRIVATE KEY-----`))
```

## Private key signing

### Input data

```go
// Input string
signer := dongle.Sign.FromString("hello world").ByRsa(kp)
// Input byte slice
signer := dongle.Sign.FromBytes([]byte("hello world")).ByRsa(kp)
// Input file stream
file, _ := os.Open("test.txt")
signer := dongle.Sign.FromFile(file).ByRsa(kp)

// Check signing error
if signer.Error != nil {
	fmt.Printf("Signing error: %v\n", signer.Error)
	return
}
```

### Output data

```go
// Output Hex-encoded signature string
hexString := signer.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40...
// Output Hex-encoded signature byte slice
hexBytes := signer.ToHexBytes()  // []byte("7fae94fd1a8b880d8d5454dd8df30c40...")

// Output Base64-encoded signature string
base64String := signer.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==...
// Output Base64-encoded signature byte slice
base64Bytes := signer.ToBase64Bytes()  // []byte("f66U/RqLiA2NVFTdjfMMQA==...")

// Output raw signature string
rawString := signer.ToRawString()
// Output raw signature byte slice
rawBytes := signer.ToRawBytes()
```

## Public key verification

> Note: The `WithXxxSign` method must be called before `ByRsa`

### Input data

```go
// Input string
verifier := dongle.Verify.FromString("hello world")
// Input byte slice
verifier := dongle.Verify.FromBytes([]byte("hello world"))
// Input file stream
file, _ := os.Open("test.txt")
verifier := dongle.Verify.FromFile(file)

// Set Hex-encoded signature
verifier.WithHexSign(rawBytes).ByRsa(kp)
// Set Base64-encoded signature
verifier.WithBase64Sign(rawBytes).ByRsa(kp)
// Set raw signature
verifier.WithRawSign(rawBytes).ByRsa(kp)

// Check verification errors
if verifier.Error != nil {
    fmt.Printf("Verification error: %v\n", verifier.Error)
    return
}
```

### Output data
```go
// Output verification result
verifier.ToBool() // true or false
```