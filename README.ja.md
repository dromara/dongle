<p align="center" style="margin-bottom: -10px"><a href="https://dongle.go-pkg.com/ja" target="_blank"><img src="https://dongle.go-pkg.com/logo.svg?v=1.1.x" width="15%" alt="dongle" /></a></p>

[![Carbon Release](https://img.shields.io/github/release/dromara/dongle.svg)](https://github.com/dromara/dongle/releases)
[![Go Test](https://github.com/dromara/dongle/actions/workflows/test.yml/badge.svg)](https://github.com/dromara/dongle/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/dromara/dongle)](https://goreportcard.com/report/github.com/dromara/dongle)
[![codecov](https://codecov.io/gh/dromara/dongle/branch/master/graph/badge.svg)](https://codecov.io/gh/dromara/dongle)
[![Carbon Doc](https://img.shields.io/badge/go.dev-reference-brightgreen?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/dromara/dongle)
[![Awesome](https://awesome.re/badge-flat2.svg)](https://github.com/avelino/awesome-go?tab=readme-ov-file#security)
[![License](https://img.shields.io/github/license/dromara/dongle)](https://github.com/dromara/dongle/blob/master/LICENSE)

日本語 | [English](README.md) | [简体中文](README.cn.md)

## プロジェクト概要

`Dongle` は、軽量で、意味的に分かりやすく、開発者に優しい `golang` エンコーディング＆暗号化ライブラリです。`100%` のユニットテストカバレッジを達成し、[awesome-go](https://github.com/avelino/awesome-go?tab=readme-ov-file#security "awesome-go") に収録されています。

## リポジトリ

[github.com/dromara/dongle](https://github.com/dromara/dongle "github.com/dromara/dongle")

[gitee.com/dromara/dongle](https://gitee.com/dromara/dongle "gitee.com/dromara/dongle")

[gitcode.com/dromara/dongle](https://gitcode.com/dromara/dongle "gitcode.com/dromara/dongle")

## クイックスタート

### インストール

> go version >= 1.23

```go
// github ライブラリを使用
go get -u github.com/dromara/dongle
import "github.com/dromara/dongle"

// gitee ライブラリを使用
go get -u gitee.com/dromara/dongle
import "gitee.com/dromara/dongle"

// gitcode ライブラリを使用
go get -u gitcode.com/dromara/dongle
import "gitcode.com/dromara/dongle"
```

`Dongle` は [dromara](https://dromara.org/ "dromara") オープンソース組織に寄贈され、リポジトリURLが変更されました。以前のパスが `golang-module/dongle` だった場合は、`go.mod` で元のアドレスを新しいパスに置き換えるか、以下のコマンドを実行してください。

```go
go mod edit -replace github.com/golang-module/dongle = github.com/dromara/dongle
```

### 使用例
エンコード・デコード(`Base64`を例に)
```go
import "github.com/dromara/dongle"

dongle.Encode.FromString("hello world").ByBase64().ToString() // aGVsbG8gd29ybGQ=
dongle.Decode.FromString("aGVsbG8gd29ybGQ=").ByBase64().ToString() // hello world
```

ハッシュアルゴリズム(`Md5`を例に)
```go
import "github.com/dromara/dongle"

dongle.Hash.FromString("hello world").ByMd5().ToHexString()    // 5eb63bbbe01eeed093cb22bb8f5acdc3
dongle.Hash.FromString("hello world").ByMd5().ToBase64String() // XrY7u+Ae7tCTyyK7j1rNww==
```

HMAC アルゴリズム(`Md5`を例に)
```go
import "github.com/dromara/dongle"

dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd5().ToHexString()    // 4790626a275f776956386e5a3ea7b726
dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd5().ToBase64String() // R5Biaidfd2lWOG5aPqe3Jg==
```

対称暗号化・復号化(`AES`を例に)
```go
import (
	"github.com/dromara/dongle"
	"github.com/dromara/dongle/crypto/cipher"
)

// 暗号器を作成
c := cipher.NewAesCipher(cipher.CBC)
// 鍵を設定（16バイト）
c.SetKey([]byte("dongle1234567890")) 
// 初期化ベクトルを設定（16バイト）
c.SetIV([]byte("1234567890123456"))
// パディングモードを設定（オプション、デフォルトはPKCS7）
c.SetPadding(cipher.PKCS7)

// 文字列平文を暗号化し、16進文字列暗号文を返す
dongle.Encrypt.FromString("hello world").ByAes(c).ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// 文字列平文を暗号化し、base64エンコード文字列暗号文を返す
dongle.Encrypt.FromString("hello world").ByAes(c).ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==

// 16進文字列暗号文を復号化し、文字列平文を返す
dongle.Decrypt.FromHexString("48c6bc076e1da2946e1c0e59e9c91ae9").ByAes(c).ToString() // hello world
// base64エンコード文字列暗号文を復号化し、文字列平文を返す
dongle.Decrypt.FromBase64String("SMa8B24dopRuHA5Z6cka6Q==").ByAes(c).ToString() // hello world
```

非対称暗号化・復号化(`RSA`を例に)
```go
import (
	"crypto"
	"github.com/dromara/dongle"
	"github.com/dromara/dongle/crypto/keypair"
)

// 鍵ペアを作成
kp := keypair.NewRsaKeyPair()
// 鍵形式を設定（オプション、デフォルトはPKCS8）
kp.SetFormat(keypair.PKCS8)
// ハッシュアルゴリズムを設定（オプション、デフォルトはSHA256）
kp.SetHash(crypto.SHA256)   

// 公開鍵を設定
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// 公開鍵で文字列平文を暗号化し、16進文字列暗号文を返す
dongle.Encrypt.FromString("hello world").ByRsa(kp).ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40...
// 公開鍵で文字列平文を暗号化し、base64エンコード文字列暗号文を返す
dongle.Encrypt.FromString("hello world").ByRsa(kp).ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==...

// 秘密鍵を設定
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
// 秘密鍵で16進文字列暗号文を復号化し、文字列平文を返す
dongle.Decrypt.FromHexString("7fae94fd1a8b880d8d5454dd8df30c40...").ByRsa(kp).ToString() // hello world
// 秘密鍵でbase64エンコード文字列暗号文を復号化し、文字列平文を返す
dongle.Decrypt.FromBase64String("f66U/RqLiA2NVFTdjfMMQA==...").ByRsa(kp).ToString() // hello world
```

デジタル署名・検証(`RSA`を例に)
```go
import (
	"crypto"
	"github.com/dromara/dongle"
	"github.com/dromara/dongle/crypto/keypair"
)

// 鍵ペアを作成
kp := keypair.NewRsaKeyPair()
// 鍵形式を設定（オプション、デフォルトはPKCS8）
kp.SetFormat(keypair.PKCS8)
// ハッシュアルゴリズムを設定（オプション、デフォルトはSHA256）
kp.SetHash(crypto.SHA256)   

// 秘密鍵を設定
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
// 秘密鍵で文字列に署名し、hex エンコードバイトスライス署名を返す
hexBytes := dongle.Sign.FromString("hello world").ByRsa(kp).ToHexBytes() // 7fae94fd1a8b880d8d5454dd8df30c40...
// 秘密鍵で文字列平文に署名し、base64 エンコードバイトスライス署名を返す
base64Bytes :=dongle.Sign.FromString("hello world").ByRsa(kp).ToBase64Bytes() // f66U/RqLiA2NVFTdjfMMQA==...

// 公開鍵を設定
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// Hex エンコード署名を設定
kp.SetHexSign(hexBytes)
// Base64 エンコード署名を設定
kp.SetBase64Sign(base64Bytes)
// 公開鍵で署名検証
dongle.Verify.FromString("hello world").ByRsa(kp).ToBool()
dongle.Verify.FromBytes([]byte("hello world")).ByRsa(kp).ToBool() 
```

より多くの使用例については、<a href="https://dongle.go-pkg.com/ja" target="_blank">公式ドキュメント</a>をご覧ください。

## コントリビューター

`dongle` に貢献してくださった以下のすべての方々に感謝いたします：

<a href="https://github.com/dromara/dongle/graphs/contributors"><img src="https://contrib.rocks/image?repo=dromara/dongle&max=80&columns=16"/></a>

## スポンサー

`Dongle` は非営利のオープンソースプロジェクトです。`dongle` をサポートしたい場合は、開発者に[コーヒーを一杯](https://dongle.go-pkg.com/ja/sponsor.html)おごることができます。

## 謝辞

`Dongle` は無料の JetBrains オープンソースライセンスの下で GoLand を使用して開発されており、ここで感謝の意を表したいと思います。

<a href="https://www.jetbrains.com" target="_blank"><img src="https://dongle.go-pkg.com/jetbrains.svg" height="50" alt="JetBrains"/></a>

## ライセンス

`Dongle` は `MIT` ライセンスの下で提供されており、詳細は [LICENSE](./LICENSE) ファイルをご覧ください。
