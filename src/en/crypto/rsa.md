---
title: RSA Asymmetric Encryption Algorithm
head:
  - - meta
    - name: description
      content: RSA asymmetric encryption algorithm, supports PKCS1 and PKCS8 key formats, supports multiple hash algorithms, uses public key encryption and private key decryption, supports standard and streaming processing, supports Hex and Base64 output formats
  - - meta
    - name: keywords
      content: dongle, go-dongle, encryption, decryption, RSA, asymmetric encryption algorithm, public key encryption, private key decryption, PKCS1, PKCS8, PSS, PKCS1v15
---

# RSA

RSA is an asymmetric encryption algorithm that uses public key for encryption and private key for decryption. `dongle` supports standard and streaming `RSA` encryption and provides multiple key formats, hash algorithms, and output formats.

Supported key formats:

- **PKCS1**: PKCS#1 format, keys use `-----BEGIN RSA PRIVATE KEY-----` and `-----BEGIN RSA PUBLIC KEY-----` as header and footer 
- **PKCS8**: PKCS#8 format, keys use `-----BEGIN PRIVATE KEY-----` and `-----BEGIN PUBLIC KEY-----` as header and footer (recommended)

Supported padding modes:

- **PKCS1v15**: PKCS#1 v1.5 padding mode, can be used for encryption and signing, good compatibility
- **OAEP**: Optimal Asymmetric Encryption Padding, only used for encryption/decryption, higher security (recommended for encryption)

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
- **Padding mode**: It is recommended to use `OAEP` for encryption/decryption
- **Hash algorithm**: It is recommended to use `SHA256` or stronger hash algorithms, avoid using `MD5` and `SHA1`
- **Data length limitation**: RSA encrypted data length is limited by key length, for large amounts of data it is recommended to use hybrid encryption
- **Private key security**: Private keys must be properly protected and cannot be leaked

Import related modules:
```go
import (
    "crypto"
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/keypair"
)
```

## Create Key Pair
```go
kp := keypair.NewRsaKeyPair()
// Set key format (optional, default is PKCS8)
kp.SetFormat(keypair.PKCS8)
// Set padding mode (optional, default is empty, PKCS1 format defaults to PKCS1v15, PKCS8 format defaults to OAEP)
kp.SetPadding(keypair.OAEP)  // or keypair.PKCS1v15
// Set hash algorithm (optional, default is SHA256, used for OAEP padding mode)
kp.SetHash(crypto.SHA256)   
```

### Generate key pair

```go
// Generate 2048-bit key pair
err := kp.GenKeyPair(2048)
if err != nil {
    panic(err)
}

// Get public key in pem format
publicKey := kp.PublicKey  
// Get private key in pem format
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
privateKey, err :=kp.CompressPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
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

## Encrypt via public key

Input Data

```go
// Input string
encrypter := dongle.Encrypt.FromString("hello world").ByRsa(kp)
// Input byte slice
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByRsa(kp)
// Input file stream
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByRsa(kp)

// Check encryption error
if encrypter.Error != nil {
	fmt.Printf("Encryption error: %v\n", encrypter.Error)
	return
}
```

Output Data

```go
// Output Hex encoded string
hexString := encrypter.ToHexString() // e.g.: 7fae94fd1a8b880d8d5454dd8df30c40...
// Output hex-encoded byte slice
hexBytes := encrypter.ToHexBytes()   // e.g.: []byte("7fae94fd1a8b880d8d5454dd8df30c40...")

// Output Base64 encoded string
base64String := encrypter.ToBase64String() // e.g.: f66U/RqLiA2NVFTdjfMMQA==...
// Output base64-encoded byte slice
base64Bytes := encrypter.ToBase64Bytes()   // e.g.: []byte("f66U/RqLiA2NVFTdjfMMQA==...")

// Output unencoded raw string
rawString := encrypter.ToRawString()
// Output unencoded raw byte slice
rawBytes := encrypter.ToRawBytes()
```

## Decrypt via private key

Input Data

```go
// Input hex-encoded string
decrypter := dongle.Decrypt.FromHexString(hexString).ByRsa(kp)
// Input hex-encoded byte slice
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByRsa(kp)
// Input hex-encoded file stream
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByRsa(kp)

// Input base64-encoded string
decrypter := dongle.Decrypt.FromBase64String(base64String).ByRsa(kp)
// Input base64-encoded byte slice
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByRsa(kp)
// Input base64-encoded file stream
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByRsa(kp)

// Input unencoded raw string
decrypter := dongle.Decrypt.FromRawString(rawString).ByRsa(kp)
// Input unencoded raw byte slice
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByRsa(kp)
// Input unencoded raw file stream
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByRsa(kp)

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
