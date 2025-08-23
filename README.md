<p align="center" style="margin-bottom: -10px"><a href="https://dongle.go-pkg.com" target="_blank"><img src="https://dongle.go-pkg.com/logo.svg?v=1.1.x" width="15%" alt="dongle" /></a></p>

[![Carbon Release](https://img.shields.io/github/release/dromara/dongle.svg)](https://github.com/dromara/dongle/releases)
[![Go Test](https://github.com/dromara/dongle/actions/workflows/test.yml/badge.svg)](https://github.com/dromara/dongle/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/dromara/dongle)](https://goreportcard.com/report/github.com/dromara/dongle)
[![codecov](https://codecov.io/gh/dromara/dongle/branch/master/graph/badge.svg)](https://codecov.io/gh/dromara/dongle)
[![Carbon Doc](https://img.shields.io/badge/go.dev-reference-brightgreen?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/dromara/dongle)
[![Awesome](https://awesome.re/badge-flat2.svg)](https://github.com/avelino/awesome-go?tab=readme-ov-file#security)
[![License](https://img.shields.io/github/license/dromara/dongle)](https://github.com/dromara/dongle/blob/master/LICENSE)

English | [简体中文](README.cn.md) | [日本語](README.ja.md)

## Introduction

`Dongle` is a simple, semantic and developer-friendly golang crypto package with `100%` unit test coverage，has been included by [awesome-go](https://github.com/avelino/awesome-go?tab=readme-ov-file#security "awesome-go-cn") and [hello-github](https://hellogithub.com/repository/dromara/dongle "hello-github") 

## Repository

[github.com/dromara/dongle](https://github.com/dromara/dongle "github.com/dromara/dongle")

[gitee.com/dromara/dongle](https://gitee.com/dromara/dongle "gitee.com/dromara/dongle")

[gitcode.com/dromara/dongle](https://gitcode.com/dromara/dongle "gitcode.com/dromara/dongle")

## Quick Start

### Installation

> go version >= 1.23

```go
// Via github 
go get -u github.com/dromara/dongle
import "github.com/dromara/dongle"

// Via gitee
go get -u gitee.com/dromara/dongle
import "gitee.com/dromara/dongle"

// Via gitcode 
go get -u gitcode.com/dromara/dongle
import "gitcode.com/dromara/dongle"
```

`Dongle` was donated to the [dromara](https://dromara.org/ "dromara") organization, the repository URL has changed. If
the previous repository used was `golang-module/dongle`, please replace the original repository with the new repository
in `go.mod`, or execute the following command:

```go
go mod edit -replace github.com/golang-module/dongle = github.com/dromara/dongle
```

### Example Usage
Encode&Decode
```go
import "github.com/dromara/dongle"

dongle.Encode.FromString("hello world").ByBase64().ToString()      // aGVsbG8gd29ybGQ=
dongle.Decode.FromString("aGVsbG8gd29ybGQ=").ByBase64().ToString() // hello world
```

Hash Algorithm
```go
import "github.com/dromara/dongle"

dongle.Hash.FromString("hello world").ByMd5().ToHexString()    // 5eb63bbbe01eeed093cb22bb8f5acdc3
dongle.Hash.FromString("hello world").ByMd5().ToBase64String() // XrY7u+Ae7tCTyyK7j1rNww==
```

Hmac Algorithm
```go
import "github.com/dromara/dongle"

dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd5().ToHexString()    // 4790626a275f776956386e5a3ea7b726
dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd5().ToBase64String() // R5Biaidfd2lWOG5aPqe3Jg==
```

Symmetric Encryption&Decryption
```go
import (
	"github.com/dromara/dongle"
	"github.com/dromara/dongle/crypto/cipher"
)

// Create cipher
c := cipher.NewAesCipher(cipher.CBC)
// Set key (16 bytes)
c.SetKey([]byte("dongle1234567890")) 
// Set initialization vector (16 bytes)
c.SetIV([]byte("1234567890123456"))
// Set padding mode (optional, default is PKCS7)
c.SetPadding(cipher.PKCS7)

// Encrypt string plaintext, return hex string ciphertext
dongle.Encrypt.FromString("hello world").ByAes(c).ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// Decrypt hex string ciphertext, return string plaintext
dongle.Decrypt.FromHexString("48c6bc076e1da2946e1c0e59e9c91ae9").ByAes(c).ToString() // hello world

// Encrypt string plaintext, return base64 encoded string ciphertext
dongle.Encrypt.FromString("hello world").ByAes(c).ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// Decrypt base64 encoded string ciphertext, return string plaintext
dongle.Decrypt.FromBase64String("SMa8B24dopRuHA5Z6cka6Q==").ByAes(c).ToString() // hello world
```

Asymmetric Encryption&Decryption
```go
import (
	"crypto"
	"github.com/dromara/dongle"
	"github.com/dromara/dongle/crypto/keypair"
)

// Create key pair
kp := keypair.NewRsaKeyPair()
// Set key format (optional, default is PKCS8)
kp.SetFormat(keypair.PKCS8)
// Set hash algorithm (optional, default is SHA256)
kp.SetHash(crypto.SHA256)   

// Set public key
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// Set private key
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))

// Encrypt string plaintext, return hex string ciphertext
dongle.Encrypt.FromString("hello world").ByRsa(kp).ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40...
// Decrypt hex string ciphertext, return string plaintext
dongle.Encrypt.FromHexString("7fae94fd1a8b880d8d5454dd8df30c40...").ByRsa(kp).ToString() // hello world

// Encrypt string plaintext, return base64 encoded string ciphertext
dongle.Encrypt.FromString("hello world").ByRsa(kp).ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==...
// Decrypt base64 encoded string ciphertext, return string plaintext
dongle.Encrypt.FromBase64String("f66U/RqLiA2NVFTdjfMMQA==...").ByRsa(kp).ToString() // hello world
```

For more usage examples, please refer to <a href="https://dongle.go-pkg.com" target="_blank">official document</a>.

## Contributors

Thanks to all the following who contributed to `dongle`:

<a href="https://github.com/dromara/dongle/graphs/contributors"><img src="https://contrib.rocks/image?repo=dromara/dongle&max=80&columns=16"/></a>

## Sponsors

`Dongle` is a non-commercial open source project. If you want to support `dongle`, you can [buy a cup of coffee](https://dongle.go-pkg.com/sponsor.html) for developer.

## Thanks

`Dongle` had been being developed with GoLand under the free JetBrains Open Source license, I would like to express my thanks here.

<a href="https://www.jetbrains.com" target="_blank"><img src="https://dongle.go-pkg.com/jetbrains.svg?v=2.6.x" height="50" alt="JetBrains"/></a>

## License

`Dongle` is licensed under the `MIT` License, see the [LICENSE](./LICENSE) file for details.
