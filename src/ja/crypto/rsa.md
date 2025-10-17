---
title: RSA暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: RSA暗号化アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: 暗号化, 復号化, RSA, 非対称暗号化アルゴリズム, 公開鍵暗号化, 秘密鍵復号化, PKCS#1, PKCS#8
---

# RSA

RSAは非対称暗号化アルゴリズムで、公開鍵で暗号化し、秘密鍵で復号化します。`dongle` は標準およびストリーミング `RSA` 暗号化をサポートし、多様な鍵形式、ハッシュアルゴリズム、出力形式を提供します。

以下の鍵形式をサポート：

- **PKCS1**：PKCS#1形式、`PKCS1v15` パディングモードを使用、ハッシュアルゴリズムの指定は`不要`
- **PKCS8**：PKCS#8形式、`PSS` パディングモードを使用、ハッシュアルゴリズムの指定が`必要`、より良いセキュリティを提供

以下のハッシュアルゴリズムをサポート：

- **MD4**：MD4ハッシュアルゴリズム（本番環境での使用は非推奨）
- **MD5**：MD5ハッシュアルゴリズム（本番環境での使用は非推奨）
- **SHA1**：SHA-1ハッシュアルゴリズム（本番環境での使用は非推奨）
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

- **鍵長**：セキュリティを確保するため、`2048` ビット以上の鍵長を推奨
- **鍵形式**：`PKCS8` 形式の使用を推奨、より安全な `OAEP` パディングモードを使用
- **ハッシュアルゴリズム**：`SHA256` 以上の強力なハッシュアルゴリズムを推奨、`MD5` と `SHA1` の使用を避ける
- **データ長制限**：RSA暗号化のデータ長は鍵長で制限され、大量データにはハイブリッド暗号化を推奨
- **秘密鍵セキュリティ**：秘密鍵は必ず適切に保管し、漏洩してはいけない

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
// 鍵形式を設定（オプション、デフォルトはPKCS8）
kp.SetFormat(keypair.PKCS8)
// ハッシュアルゴリズムを設定（オプション、デフォルトはSHA256）
kp.SetHash(crypto.SHA256)   
```

### 鍵ペアの生成

```go
// 2048ビット鍵ペアを生成
kp.GenKeyPair(2048)

// PEM形式公開鍵を取得
publicKey := kp.PublicKey  
// PEM形式秘密鍵を取得
privateKey := kp.PrivateKey
```

### 既存PEM鍵から鍵ペアを設定

```go
// PEM形式公開鍵を設定
kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHq
X1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJ
y4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMez
HC1outlM6x+/BB0BSQIDAQAB
-----END PUBLIC KEY-----`)

// PEM形式秘密鍵を設定
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

### 既存PEM鍵ファイルから鍵ペアを読み込み

```go
// PEMファイルから公開鍵を読み込み
publicKeyFile, _ := os.Open("public_key.pem")
kp.LoadPublicKey(publicKeyFile)

// PEMファイルから秘密鍵を読み込み
privateKeyFile, _ := os.Open("private_key.pem")
kp.LoadPrivateKey(privateKeyFile)
```

### 既存文字列鍵から鍵ペアを設定

```go
// 文字列形式公開鍵を設定、対応するPEM形式公開鍵に自動変換
kp.SetPublicKey([]byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqzZNa9VrcewyU6wDoV7Y9kAHqX1VK0B3Rb6GNmQe4zLEfce7cVTaLrc4VGTKl35tADG1cRHqtaG4S/WttpiGZBhxJy4MpOXb6eIPiVLsn2lL+rJo5XdbSr3gyjxEOQQ97ihtw4lDd5wMo4bIOuw1LtMezHC1outlM6x+/BB0BSQIDAQAB"))
// 文字列形式秘密鍵を設定、対応するPEM形式秘密鍵に自動変換
kp.SetPrivateKey([]byte("MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKrNk1r1Wtx7DJTrAOhXtj2QAepfVUrQHdFvoY2ZB7jMsR9x7txVNoutzhUZMqXfm0AMbVxEeq1obhL9a22mIZkGHEnLgyk5dvp4g+JUuyfaUv6smjld1tKveDKPEQ5BD3uKG3DiUN3nAyjhsg67DUu0x7McLWi62UzrH78EHQFJAgMBAAECgYAeo3nHWzPNURVUsUMcan96U5bEYA2AugxfQVMNf2HvOGidZ2adh3udWrQY/MglERNcTd5gKriG2rDEH0liBecIrNKsBL4lV+qHEGRUcnDDdtUBdGInEU8lve5keDgmX+/huXSRJ+3tYA5u9j+32RquVczvIdtb5XnBLUl61k0osQJBAON5+eJjtw6xpn+pveU92BSHvaJYVyrLHwUjR07aNKb7GlGVM3MGf1FCa8WQUo9uUzYxGLtg5Qf3sqwOrwPd5UsCQQDAOF/zWqGuY3HfV/1wgiXiWp8rc+S8tanMj5M37QQbYW5YLjUmJImoklVahv3qlgLZdEN5ZSueM5jfoSFtNts7AkBKoRDvSiGbi4MBbTHkzLZgfewkH/FxE7S4nctePk553fXTgCyh9ya8BRuQdHnxnpNkOxVPHEnnpEcVFbgrf5gjAkB7KmRI4VTiEfRgINhTJAG0VU7SH/N7+4cufPzfA+7ywG5c8Fa79wOB0SoB1KeUjcSLo5Ssj2fwea1F9dAeU90LAkBJQFofveaDa3YlN4EQZOcCvJKmg7xwWuGxFVTZDVVEws7UCQbEOEEXZrNd9x0IF5kpPLR+rxuaRPgUNaDGIh5o"))
```

## 公開鍵暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByRsa(kp)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByRsa(kp)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByRsa(kp)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
hexString := encrypter.ToHexString() // 例：7fae94fd1a8b880d8d5454dd8df30c40...
// Hexエンコードバイトスライスを出力
hexBytes := encrypter.ToHexBytes()  // 例：[]byte("7fae94fd1a8b880d8d5454dd8df30c40...")

// Base64エンコード文字列を出力
base64String := encrypter.ToBase64String() // 例：f66U/RqLiA2NVFTdjfMMQA==...
// Base64エンコードバイトスライスを出力
base64Bytes := encrypter.ToBase64Bytes()  // 例：[]byte("f66U/RqLiA2NVFTdjfMMQA==...")

// エンコードされていない生の文字列を出力
rawString := encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
rawBytes := encrypter.ToRawBytes()  
```
## 秘密鍵復号化

入力データ
```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByRsa(kp)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByRsa(kp)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByRsa(kp)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByRsa(kp)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByRsa(kp)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByRsa(kp)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByRsa(kp)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByRsa(kp)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByRsa(kp)

// 復号化エラーをチェック
if decrypter.Error != nil {
	fmt.Printf("復号化エラー: %v\n", decrypter.Error)
	return
}
```

出力データ
```go
// 復号化後の文字列を出力
decrypter.ToString() // hello world
// 復号化後のバイトスライスを出力
decrypter.ToBytes() // []byte("hello world")
```