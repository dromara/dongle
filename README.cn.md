<p align="center" style="margin-bottom: -10px"><a href="https://dongle.go-pkg.com/zh" target="_blank"><img src="https://dongle.go-pkg.com/logo.svg?v=1.1.x" width="15%" alt="dongle" /></a></p>

[![Carbon Release](https://img.shields.io/github/release/dromara/dongle.svg)](https://github.com/dromara/dongle/releases)
[![Go Test](https://github.com/dromara/dongle/actions/workflows/test.yml/badge.svg)](https://github.com/dromara/dongle/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/dromara/dongle)](https://goreportcard.com/report/github.com/dromara/dongle)
[![codecov](https://codecov.io/gh/dromara/dongle/branch/master/graph/badge.svg)](https://codecov.io/gh/dromara/dongle)
[![Carbon Doc](https://img.shields.io/badge/go.dev-reference-brightgreen?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/dromara/dongle)
[![Awesome](https://awesome.re/badge-flat2.svg)](https://github.com/avelino/awesome-go#date-and-time)
[![License](https://img.shields.io/github/license/dromara/dongle)](https://github.com/dromara/dongle/blob/master/LICENSE)

简体中文 | [English](README.md) | [日本語](README.ja.md) 

## 项目简介

`Dongle` 是一个轻量级、语义化、对开发者友好的 `golang` 编码&密码库，`100%` 单元测试覆盖率，已被 [awesome-go](https://github.com/yinggaozhen/awesome-go-cn#安全 "awesome-go-cn") 收录，并获得
`gitee` 2024 年最有价值项目（`GVP`）和 `gitcode` 2024 年度开源摘星计划 (`G-Star`) 项目

<img src="https://dongle.go-pkg.com/gvp.jpg?v=1.1.x" width="100%" alt="gvp"/>
<img src="https://dongle.go-pkg.com/gstar.jpg?v=1.1.x" width="100%" alt="g-star"/>

## 仓库地址

[github.com/dromara/dongle](https://github.com/dromara/dongle "github.com/dromara/dongle")

[gitee.com/dromara/dongle](https://gitee.com/dromara/dongle "gitee.com/dromara/dongle")

[gitcode.com/dromara/dongle](https://gitcode.com/dromara/dongle "gitcode.com/dromara/dongle")

## 快速开始

### 安装使用

> go version >= 1.23

```go
// 使用 github 库
go get -u github.com/dromara/dongle

// 使用 gitee 库
go get -u gitee.com/dromara/dongle

// 使用 gitcode 库
go get -u gitcode.com/dromara/dongle
```

`Dongle` 已经捐赠给了 [dromara](https://dromara.org/ "dromara") 开源组织，仓库地址发生了改变，如果之前用的路径是
`golang-module/dongle`，请在 `go.mod` 里将原地址更换为新路径，或执行如下命令

```go
go mod edit -replace github.com/golang-module/dongle = github.com/dromara/dongle
```

### 用法示例
编码、解码(以 `Base64` 为例)
```go
import (
    "github.com/dromara/dongle"
)

dongle.Encode.FromString("hello world").ByBase64().ToString() // aGVsbG8gd29ybGQ=
dongle.Decode.FromString("aGVsbG8gd29ybGQ=").ByBase64().ToString() // hello world
```

Hash 算法(以 `Md5` 为例)
```go
import (
    "github.com/dromara/dongle"
)

dongle.Hash.FromString("hello world").ByMd5().ToHexString()    // 5eb63bbbe01eeed093cb22bb8f5acdc3
dongle.Hash.FromString("hello world").ByMd5().ToBase64String() // XrY7u+Ae7tCTyyK7j1rNww==
```

Hmac 算法(以 `Md5` 为例)
```go
import (
    "github.com/dromara/dongle"
)

dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd5().ToHexString()    // 4790626a275f776956386e5a3ea7b726
dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd5().ToBase64String() // R5Biaidfd2lWOG5aPqe3Jg==
```

对称加密(以 `AES` 为例)
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)

// 创建密钥器
c := cipher.NewAesCipher(cipher.CBC)
// 设置密钥（16 字节)
c.SetKey([]byte("dongle1234567890")) 
// 设置初始化向量（16 字节)
c.SetIV([]byte("1234567890123456"))
// 设置填充模式（可选，默认为 PKCS7，只有 CBC/ECB 分组模式才需要设置填充模式）
c.SetPadding(cipher.PKCS7)

// 对字符串明文进行加密, 返回 hex 编码字符串密文
dongle.Encrypt.FromString("hello world").ByAes(c).ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// 对字符串明文进行加密, 返回 base64 编码字符串密文
dongle.Encrypt.FromString("hello world").ByAes(c).ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==

// 对 hex 编码字符串密文进行解密, 返回字符串明文
dongle.Decrypt.FromHexString("48c6bc076e1da2946e1c0e59e9c91ae9").ByAes(c).ToString() // hello world
// 对 base64 编码字符串密文进行解密, 返回字符串明文
dongle.Decrypt.FromBase64String("SMa8B24dopRuHA5Z6cka6Q==").ByAes(c).ToString() // hello world
```

非对称加密(以 `RSA` 为例)
```go
import (
    "crypto"
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/keypair"
)

// 创建密钥对
kp := keypair.NewRsaKeyPair()
// 设置密钥格式（可选，默认为 PKCS8）
kp.SetFormat(keypair.PKCS8)
// 设置哈希算法（可选，默认为 SHA256，只有 PKCS8 密钥格式才需要设置哈希算法）
kp.SetHash(crypto.SHA256)   

// 设置公钥
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// 通过公钥对字符串明文进行加密, 返回 hex 编码字符串密文
dongle.Encrypt.FromString("hello world").ByRsa(kp).ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40...
// 通过公钥对字符串明文进行加密, 返回 base64 编码字符串密文
dongle.Encrypt.FromString("hello world").ByRsa(kp).ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==...

// 设置私钥
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
// 通过私钥对 hex 编码字符串密文进行解密, 返回字符串明文
dongle.Decrypt.FromHexString("7fae94fd1a8b880d8d5454dd8df30c40...").ByRsa(kp).ToString() // hello world
// 通过私钥对 base64 编码字符串密文进行解密, 返回字符串明文
dongle.Decrypt.FromBase64String("f66U/RqLiA2NVFTdjfMMQA==...").ByRsa(kp).ToString() // hello world
```

数字签名、验证(以 `RSA` 为例)
```go
import (
    "crypto"
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/keypair"
)

// 创建密钥对
kp := keypair.NewRsaKeyPair()
// 设置密钥格式（可选，默认为 PKCS8）
kp.SetFormat(keypair.PKCS8)
// 设置哈希算法（可选，默认为 SHA256，只有 PKCS8 密钥格式才需要设置哈希算法）
kp.SetHash(crypto.SHA256)   

// 设置私钥
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
// 通过私钥对字符串进行签名, 返回 hex 编码字节切片签名
hexBytes := dongle.Sign.FromString("hello world").ByRsa(kp).ToHexBytes() // 7fae94fd1a8b880d8d5454dd8df30c40...
// 通过私钥对字符串明文进行签名, 返回 base64 编码字节切片签名
base64Bytes :=dongle.Sign.FromString("hello world").ByRsa(kp).ToBase64Bytes() // f66U/RqLiA2NVFTdjfMMQA==...

// 设置公钥
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// 通过公钥对 hex 编码签名进行验签
dongle.Verify.FromString("hello world").WithHexSign(hexBytes).ByRsa(kp).ToBool()
// 通过公钥对 Base64 编码签名进行验签
dongle.Verify.FromString("hello world").WithBase64Sign(hexBytes).ByRsa(kp).ToBool()
```

更多用法示例请查看 <a href="https://dongle.go-pkg.com/zh" target="_blank">官方文档</a>

## 贡献者

感谢以下所有为 `dongle` 做出贡献的人：

<a href="https://github.com/dromara/dongle/graphs/contributors"><img src="https://contrib.rocks/image?repo=dromara/dongle&max=80&columns=16"/></a>

## 赞助

`Dongle` 是一个非商业开源项目, 如果你想支持 `dongle`, 你可以为开发者 [购买一杯咖啡](https://dongle.go-pkg.com/zh/sponsor.html)

## 致谢

`Dongle` 已获取免费的 `JetBrains` 开源许可证，在此表示感谢

<a href="https://www.jetbrains.com" target="_blank"><img src="https://dongle.go-pkg.com/jetbrains.svg" height="50" alt="JetBrains"/></a>

## 开源协议

`Dongle` 遵循 `MIT` 开源协议, 请参阅 [LICENSE](./LICENSE) 查看详细信息。
