---
head:
  - - meta
    - name: description
      content: Change Log | A lightweight, semantic and developer-friendly golang encoding & crypto library
---

# Change Log
## [v1.2.1](https://github.com/dromara/dongle/compare/v1.2.0...v1.2.1) (2025-11-24)

* Fix bug where `wNAF` algorithm error in `Sm2` asymmetric elliptic curve encryption algorithm causes decryption failure in some cases
* Optimize curve field element operation implementation in `Sm2` asymmetric elliptic curve encryption algorithm
* Add direct parsing support for `BIT_STRING` format keys in `Sm2` asymmetric elliptic curve encryption algorithm
* Simplify test loop syntax, change from `for` loop to `range` loop

## [v1.2.0](https://github.com/dromara/dongle/compare/v1.1.8...v1.2.0) (2025-11-11)

* Remove `LoadPublicKey` and `LoadPrivateKey` methods from `RSAKeyPair` struct
* Remove `LoadPublicKey` and `LoadPrivateKey` methods from `Ed25519KeyPair` struct
* Optimize encoder and decoder performance, reuse read buffer, reduce memory allocation and copying
* `RSAKeyPair` struct's `GenKeyPair`, `SetPublicKey`, `SetPrivateKey` methods changed from no return value to returning `error`
* `Ed25519KeyPair` struct's `GenKeyPair`, `SetPublicKey`, `SetPrivateKey` methods changed from no return value to returning `error`
* `RSAKeyPair` struct adds `FormatPublicKey` and `FormatPrivateKey` methods to format `base64` encoded `der` format `RSA` public and private keys into `pem` format
* `Ed25519KeyPair` struct adds `FormatPublicKey` and `FormatPrivateKey` methods to format `base64` encoded `der` format `Ed25519` public and private keys into `pem` format
* `RSAKeyPair` struct adds `CompressPublicKey` and `CompressPrivateKey` methods to compress `pem` format `RSA` public and private keys into `base64` encoded `der` format
* `Ed25519KeyPair` struct adds `CompressPublicKey` and `CompressPrivateKey` methods to compress `pem` format `Ed25519` public and private keys into `base64` encoded `der` format
* Add `Sm2` asymmetric elliptic curve encryption algorithm support, including standard processing and streaming processing

## [v1.1.8](https://github.com/dromara/dongle/compare/v1.1.7...v1.1.8) (2025-11-05)
* Fix bug where `*RsaKeyPair.formatPublicKey` and `*RsaKeyPair.formatPrivateKey` fail to format keys
* Fix bug where `*Ed25519KeyPair.formatPublicKey` and `*Ed25519KeyPair.formatPrivateKey` fail to format keys
* Fix bug where decoding encrypted ciphertext fails during decryption and the error cannot be retrieved
* Change default padding mode from `PKCS7` to `No` in symmetric block encryption algorithms
* Add `Unicode` encoding/decoding support, including standard processing and streaming processing
* Add `TBC` padding mode support for symmetric block encryption algorithms

## [v1.1.7](https://github.com/dromara/dongle/compare/v1.1.6...v1.1.7) (2025-10-20)

* Fix bug in asymmetric digital signature algorithm verification [#30](https://github.com/dromara/dongle/issues)
* Optimize streaming processing logic, add support for `reader` position reset to ensure reading from the beginning of the data source, avoiding position offset issues caused by previous read operations, ensuring completeness and correctness of streaming operations
* Change private methods `newXXXEncrypter` and `newXXXDecrypter` series in `crypto/cipher/block.go` to public methods `NewXXXEncrypter` and `NewXXXDecrypter`
* Change private methods `newXXXPadding` and `newXXXUnPadding` series in `crypto/cipher/padding.go` to public methods `NewXXXPadding` and `NewXXXUnPadding`
* Add `sm4` chinese national standard block encryption algorithm support, including standard processing and streaming processing, supporting different block modes and padding modes

## [v1.1.6](https://github.com/dromara/dongle/compare/v1.1.5...v1.1.6) (2025-10-12)

* Use `io.CopyBuffer` to simplify streaming processing logic
* Optimize `tea` encryption algorithm to support different block modes and padding modes
* Add `xtea` encryption algorithm support, including standard processing and streaming processing

## [v1.1.5](https://github.com/dromara/dongle/compare/v1.1.4...v1.1.5) (2025-10-01)

* Fix bug where symmetric encryption algorithms incorrectly perform padding on block modes that don't require padding (such as CFB/OFB/CTR/GCM, etc.), causing encryption/decryption errors

## [v1.1.4](https://github.com/dromara/dongle/compare/v1.1.3...v1.1.4) (2025-09-23)

* Change method receivers from pointer to value to prevent property pollution when using global default instances, with no impact on caller `API`
* Add `twofish` encryption algorithm support, including standard processing and streaming processing

## [v1.1.3](https://github.com/dromara/dongle/compare/v1.1.2...v1.1.3) (2025-09-15)

* Optimize `3DES` symmetric encryption algorithm compatibility with `16`-byte keys
* Optimize `DES` symmetric encryption algorithm validation for unsupported `GCM` mode
* Optimize `3DES` symmetric encryption algorithm validation for unsupported `GCM` mode
* Optimize `Blowfish` symmetric encryption algorithm validation for unsupported `GCM` mode
* Update `testify` dependency to `v1.11.1`
* Add `Salsa20` encryption algorithm support, including standard processing and streaming processing

## [v1.1.2](https://github.com/dromara/dongle/compare/v1.1.1...v1.1.2) (2025-09-08)

* Encoding/decoding support customizing file stream buffer size via `coding.BufferSize` global variable
* Encryption/decryption support customizing file stream buffer size via `crypto.BufferSize` global variable
* Hash/Hmac algorithms support customizing file stream buffer size via `hash.BufferSize` global variable
* Add `Blake2b` hash algorithm support, including `blake2b-256`, `blake2b-384` and `blake2b-512`
* Add `Blake2s` hash algorithm support, including `blake2s-128` and `blake2s-256`
* Add `ChaCha20` encryption algorithm support
* Add `ChaCha20Poly1305` encryption algorithm support

## [v1.1.1](https://github.com/dromara/dongle/compare/v1.1.0...v1.1.1) (2025-09-01)

* Symmetric encryption algorithms changed from `ByXXX(cipher.XXXCipher)` to `ByXXX(*cipher.XXXCipher)`
* Change toolkit package name from `utils` to `util`
* Encoding/decoding, encryption/decryption, Hash/Hmac, signature/verification support true streaming processing
* When input data is empty, return empty data directly without executing subsequent operations
* Add `ED25519` digital signature and verification support
* Add `SM3` hash algorithm support
* Add `mock/hash.go` to simulate errors in `hash.Hash` interface
* `coding/morse/morse.go` adds support for spaces, punctuation, and special characters

## [v1.1.0](https://github.com/dromara/dongle/compare/v1.0.1...v1.1.0) (2025-08-23)
> ⚠️ This is a breaking change version, please upgrade with caution, but it is strongly recommended to upgrade

* Delete `BySafeURL` encoding/decoding method
* Delete `Sm3` hash algorithm (`hash`) and message authentication code algorithm (`hmac`)
* Rename `ByBase64URL` encoding/decoding method to `ByBase64Url`
* Hash algorithm (`hash`) calling method changed from `dongle.Encrypt.ByXXX()` to `dongle.Hash.ByXXX()`
* Message authentication code algorithm (`hmac`) calling method changed from `dongle.Encrypt.ByHmacXXX()` to `dongle.Hash.WithKey().ByXXX()`
* Refactor `AES`, `DES`, `3DES`, `Blowfish` and other symmetric encryption/decryption methods, uniformly use `cipher.NewXXXCipher()`
* Refactor `RSA` and other asymmetric encryption/decryption methods, uniformly use `keypair.NewXXXKeyPair()`
* Add support for `file stream` encoding/decoding, encryption/decryption, Hash/HMAC, signature/verification
* Add new `ByBase32Hex` encoding/decoding method
* Add support for `base32/base32Hex` encoding custom character
* Add support for `base45` encoding custom character
* Add support for `base62` encoding custom character
* Add support for `base64/base64Url` encoding custom character

## [v1.0.1](https://github.com/dromara/dongle/compare/v1.0.0...v1.0.1) (2024-11-22)

* Optimize code quality and organizational structure
* Fix bug with `AES-CBC-PKCS5` encryption/decryption errors
* `base62` supports custom encoding tables
* Delete `errors.go` file, migrate error messages to individual files
* Unify unit test format
* Remove Chinese comments

## [v1.0.0](https://github.com/dromara/carbon/compare/v0.2.8...v1.0.0) (2024-11-11)

- Fixed panic caused by AES/ECB/PKCS5 padding
- Changed repository and badge urls

For change logs of earlier versions, please refer to <a href="https://github.com/dromara/dongle/releases" target="_blank" rel="noreferrer">releases</a>