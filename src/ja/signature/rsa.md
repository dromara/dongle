---
title: RSAデジタル署名アルゴリズム
head:
  - - meta
    - name: description
      content: RSAデジタル署名アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: rsa, デジタル署名, 署名検証, 非対称暗号, 公開鍵署名
---

# RSA

RSAデジタル署名は非対称暗号ベースのデジタル署名アルゴリズムで、秘密鍵で署名し、公開鍵で検証します。`dongle` は標準的な `RSA` デジタル署名をサポートし、多様な鍵フォーマット、ハッシュアルゴリズム、出力形式を提供します。

以下の鍵フォーマットをサポート：

- **PKCS1**：PKCS#1 フォーマット、`PKCS1v15` パディングモードを使用、ハッシュアルゴリズムの指定は`不要`
- **PKCS8**：PKCS#8 フォーマット、`PSS` パディングモードを使用、ハッシュアルゴリズムの指定が`必須`、より優れたセキュリティを提供

以下のハッシュアルゴリズムをサポート：

- **MD4**：MD4ハッシュアルゴリズム（本番環境での使用非推奨）
- **MD5**：MD5ハッシュアルゴリズム（本番環境での使用非推奨）
- **SHA1**：SHA-1ハッシュアルゴリズム（本番環境での使用非推奨）
- **SHA224**：SHA-224ハッシュアルゴリズム
- **SHA256**：SHA-256ハッシュアルゴリズム（推奨）
- **SHA384**：SHA-384ハッシュアルゴリズム
- **SHA512**：SHA-512ハッシュアルゴリズム
- **MD5SHA1**：MD5-SHA1ハッシュアルゴリズム
- **RIPEMD160**：RIPEMD160ハッシュアルゴリズム
- **SHA3_224**：SHA3_224ハッシュアルゴリズム
- **SHA3_256**：SHA3_256ハッシュアルゴリズム
- **SHA3_384**：SHA3_384ハッシュアルゴリズム
- **SHA3_512**：SHA3_512ハッシュアルゴリズム
- **SHA512_224**：SHA512_224ハッシュアルゴリズム
- **SHA512_256**：SHA512_256ハッシュアルゴリズム
- **BLAKE2s_256**：BLAKE2s_256ハッシュアルゴリズム
- **BLAKE2b_256**：BLAKE2b_256ハッシュアルゴリズム
- **BLAKE2b_384**：BLAKE2b_384ハッシュアルゴリズム
- **BLAKE2b_512**：BLAKE2b_512ハッシュアルゴリズム

注意事項：

- **鍵長**：セキュリティを確保するため、`2048` ビット以上の鍵長を使用することを推奨
- **鍵フォーマット**：より安全な `PSS` パディングモードを使用する `PKCS8` フォーマットを推奨
- **ハッシュアルゴリズム**：`SHA256` 以上の強力なハッシュアルゴリズムを推奨し、`MD5` と `SHA1` の使用は避ける
- **秘密鍵のセキュリティ**：秘密鍵は適切に保管し、漏洩してはいけません、秘密鍵の所有者のみが有効な署名を生成できます
- **署名検証**：誰でも公開鍵を使って署名の有効性を検証できます

関連モジュールをインポート：
```go
import (
    "crypto"
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/keypair"
)
```

## 鍵ペアの作成
```go
kp := keypair.NewRsaKeyPair()
// 鍵フォーマットを設定（オプション、デフォルトは PKCS8）
kp.SetFormat(keypair.PKCS8)
// ハッシュアルゴリズムを設定（オプション、デフォルトは SHA256）
kp.SetHash(crypto.SHA256)   
```

### 鍵ペアの生成

```go
// 2048 ビット鍵ペアを生成
kp.GenKeyPair(2048)

// PEM フォーマット公開鍵を取得
publicKey := kp.PublicKey  
// PEM フォーマット秘密鍵を取得
privateKey := kp.PrivateKey
```

### 既存の PEM 鍵から鍵ペアを設定

```go
// PEM フォーマット公開鍵を設定
kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHq
X1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJ
y4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMez
HC1outlM6x+/BB0BSQIDAQAB
-----END PUBLIC KEY-----`)

// PEM フォーマット秘密鍵を設定
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

### 既存の PEM 鍵ファイルから鍵ペアを読み込み

```go
// PEM ファイルから公開鍵を読み込み
publicKeyFile, _ := os.Open("public_key.pem")
kp.LoadPublicKey(publicKeyFile)

// PEM ファイルから秘密鍵を読み込み
privateKeyFile, _ := os.Open("private_key.pem")
kp.LoadPrivateKey(privateKeyFile)
```

### 既存の文字列鍵から鍵ペアを設定

```go
// 文字列フォーマット公開鍵を設定、対応するPEMフォーマット公開鍵に自動変換
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// 文字列フォーマット秘密鍵を設定、対応するPEMフォーマット秘密鍵に自動変換
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
```

## 秘密鍵署名

### 入力データ

```go
// 入力文字列
signer := dongle.Sign.FromString("hello world").ByRsa(kp)
// 入力バイトスライス
signer := dongle.Sign.FromBytes([]byte("hello world")).ByRsa(kp)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
signer := dongle.Sign.FromFile(file).ByRsa(kp)

// 署名エラーをチェック
if signer.Error != nil {
	fmt.Printf("署名エラー: %v\n", signer.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード署名文字列を出力
hexString := signer.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40...
// Hexエンコード署名バイトスライスを出力
hexBytes := signer.ToHexBytes()  // []byte("7fae94fd1a8b880d8d5454dd8df30c40...")

// Base64エンコード署名文字列を出力
base64String := signer.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==...
// Base64エンコード署名バイトスライスを出力
base64Bytes := signer.ToBase64Bytes()  // []byte("f66U/RqLiA2NVFTdjfMMQA==...")

// エンコードなし生署名文字列を出力
rawString := signer.ToRawString()
// エンコードなし生署名バイトスライスを出力
rawBytes := signer.ToRawBytes()
```

## 公開鍵検証
> 注意：`WithXxxSign` メソッドは `ByRsa` の前に呼び出す必要があります

### 入力データ

```go
// 入力文字列
verifier := dongle.Verify.FromString("hello world")
// 入力バイトスライス
verifier := dongle.Verify.FromBytes([]byte("hello world"))
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
verifier := dongle.Verify.FromFile(file)

// Hexエンコード署名を設定
verifier.WithHexSign(hexString).ByRsa(kp)
// Base64エンコード署名を設定
verifier.WithBase64Sign(base64String).ByRsa(kp)
// エンコードなし生署名を設定
verifier.WithRawSign(rawBytes).ByRsa(kp)

// 検証エラーをチェック
if verifier.Error != nil {
    fmt.Printf("検証エラー: %v\n", verifier.Error)
    return
}
```

### 出力データ
```go
// 検証結果を出力
verifier.ToBool() // true または false
```