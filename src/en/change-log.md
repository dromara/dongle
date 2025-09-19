---
head:
  - - meta
    - name: description
      content: Change Log | A lightweight, semantic and developer-friendly golang encoding & crypto library
---

# Change Log
## [v1.1.3](https://github.com/dromara/dongle/compare/v1.1.2...v1.1.3) (2025-09-15)

* [chore] Optimize `3DES` symmetric encryption algorithm compatibility with `16`-byte keys
* [chore] Optimize `DES` symmetric encryption algorithm validation for unsupported `GCM` mode
* [chore] Optimize `3DES` symmetric encryption algorithm validation for unsupported `GCM` mode
* [chore] Optimize `Blowfish` symmetric encryption algorithm validation for unsupported `GCM` mode
* [chore] Update `testify` dependency to `v1.11.1`

* [feat] Add `Salsa20` encryption algorithm support, including standard processing and streaming processing

## [v1.1.2](https://github.com/dromara/dongle/compare/v1.1.1...v1.1.2) (2025-09-08)

* [chore] Encoding/decoding support customizing file stream buffer size via `coding.BufferSize` global variable
* [chore] Encryption/decryption support customizing file stream buffer size via `crypto.BufferSize` global variable
* [chore] Hash/Hmac algorithms support customizing file stream buffer size via `hash.BufferSize` global variable

* [feat] Add `Blake2b` hash algorithm support, including `blake2b-256`, `blake2b-384` and `blake2b-512`
* [feat] Add `Blake2s` hash algorithm support, including `blake2s-128` and `blake2s-256`
* [feat] Add `ChaCha20` encryption algorithm support
* [feat] Add `ChaCha20Poly1305` encryption algorithm support

## [v1.1.1](https://github.com/dromara/dongle/compare/v1.1.0...v1.1.1) (2025-09-01)

* [refactor] Symmetric encryption algorithms changed from `ByXXX(cipher.XXXCipher)` to `ByXXX(*cipher.XXXCipher)`
* [refactor] Change toolkit package name from `utils` to `util`
* [refactor] Encoding/decoding, encryption/decryption, Hash/Hmac, signature/verification support true streaming processing
* [refactor] When input data is empty, return empty data directly without executing subsequent operations

* [feat] Add `ED25519` digital signature and verification support
* [feat] Add `SM3` hash algorithm support
* [feat] Add `mock/hash.go` to simulate errors in `hash.Hash` interface
* [feat] `coding/morse/morse.go` adds support for spaces, punctuation, and special characters

## [v1.1.0](https://github.com/dromara/dongle/compare/v1.0.1...v1.1.0) (2025-08-23)
> ⚠️ This is a breaking change version, please upgrade with caution, but it is strongly recommended to upgrade

* [refactor] Delete `BySafeURL` encoding/decoding method
* [refactor] Delete `Sm3` hash algorithm (`hash`) and message authentication code algorithm (`hmac`)
* [refactor] Rename `ByBase64URL` encoding/decoding method to `ByBase64Url`
* [refactor] Hash algorithm (`hash`) calling method changed from `dongle.Encrypt.ByXXX()` to `dongle.Hash.ByXXX()`
* [refactor] Message authentication code algorithm (`hmac`) calling method changed from `dongle.Encrypt.ByHmacXXX()` to `dongle.Hash.WithKey().ByXXX()`
* [refactor] Refactor `AES`, `DES`, `3DES`, `Blowfish` and other symmetric encryption/decryption methods, uniformly use `cipher.NewXXXCipher()`
* [refactor] Refactor `RSA` and other asymmetric encryption/decryption methods, uniformly use `keypair.NewXXXKeyPair()`

* [feat] Add support for `file stream` encoding/decoding, encryption/decryption, Hash/HMAC, signature/verification
* [feat] Add new `ByBase32Hex` encoding/decoding method
* [feat] Add support for `base32/base32Hex` encoding custom character
* [feat] Add support for `base45` encoding custom character
* [feat] Add support for `base62` encoding custom character
* [feat] Add support for `base64/base64Url` encoding custom character

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