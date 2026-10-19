---
title: SM2 非対称楕円曲線暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: SM2 非対称暗号化アルゴリズム、中国国家暗号管理局が制定した国産商用暗号アルゴリズム、楕円曲線暗号に基づき、生バイトの C1C3C2・C1C2C3 暗号文順序に加えて ASN1C1C3C2・ASN1C1C2C3 の ASN.1 DER 形式をサポート、公開鍵暗号化と秘密鍵復号化を使用、標準およびストリーム処理をサポート、Hex と Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, 暗号化, 復号化, SM2, 非対称暗号化アルゴリズム, 公開鍵暗号化, 秘密鍵復号化, 国密アルゴリズム, 楕円曲線, C1C3C2, C1C2C3, ASN1C1C3C2, ASN1C1C2C3, PKCS8, SPKI
---

# SM2

SM2 は中国国家暗号管理局が制定した楕円曲線公開鍵暗号アルゴリズム（GM/T 0003-2012）であり、中国の商用暗号標準の中核アルゴリズムの一つです。`dongle` は標準およびストリーム `SM2` 暗号化をサポートし、複数の暗号文形式とパフォーマンス最適化オプションを提供します。

以下の暗号文形式をサポート（`Sm2CipherMode` で指定）：

- **C1C3C2**：国密標準推奨形式（デフォルト）、生バイト構造は `0x04 || C1(64バイト) || C3(32バイト) || C2(暗号文データ)`
  - C1：楕円曲線点（乱数生成）
  - C3：SM3 メッセージダイジェスト（完全性検証用）
  - C2：暗号化されたデータ
- **C1C2C3**：旧標準互換形式、生バイト構造は `0x04 || C1(64バイト) || C2(暗号文データ) || C3(32バイト)`
- **ASN1C1C3C2**：ASN.1 DER 形式、暗号文は `SEQUENCE { x INTEGER, y INTEGER, C3 OCTET STRING, C2 OCTET STRING }`、BouncyCastle・Java・大半の国密ゲートウェイのデフォルト出力で、**`0x04` プレフィックスは付きません**
- **ASN1C1C2C3**：ASN.1 DER 形式、暗号文は `SEQUENCE { x INTEGER, y INTEGER, C2 OCTET STRING, C3 OCTET STRING }`

> 2 つの ASN.1 形式は `cryptobyte` で解析されるため、切り詰められたデータや不正な DER は黙って誤読されず、エラーとして返されます。

以下のパフォーマンス最適化オプションをサポート：

- **Window ウィンドウサイズ**：楕円曲線演算の事前計算ウィンドウを制御（2-6）、デフォルトは 4
  - ウィンドウが大きいほど暗号化速度が速くなりますが、メモリ使用量がわずかに増加します
  - 最適なパフォーマンスを得るには、デフォルト値 4 または 5 の使用を推奨

注意事項：

- **鍵形式**：秘密鍵は `PKCS#8` 形式で保存、公開鍵は `SPKI/PKIX` 形式で保存
- **暗号文形式**：暗号化と復号化は同じ `Sm2CipherMode`（`C1C3C2`、`C1C2C3`、`ASN1C1C3C2`、`ASN1C1C2C3` のいずれか）を使用する必要があります
- **鍵素材**：`SetPublicKey` / `SetPrivateKey` は PEM に加えて、base64 または hex でエンコードされた DER、および生の鍵素材（公開鍵は 65 バイトの非圧縮点、秘密鍵は 32 バイトのスカラー）を受け取り、PEM に正規化します
- **データセキュリティ**：SM2 は 128 ビットのセキュリティ強度を提供し、RSA 3072 ビットに相当
- **相互運用性**：OpenSSL、BouncyCastle、Java などのライブラリと相互運用する際は、相手側の暗号文形式を確認してください。大半の国密ゲートウェイは ASN.1 形式を出力します
- **秘密鍵のセキュリティ**：秘密鍵は適切に保管し、漏洩してはいけません
- **標準準拠**：GM/T 0003.4-2012（暗号化アルゴリズム）および GM/T 0003.5-2012（曲線パラメータ）に完全準拠

関連モジュールのインポート：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/keypair"
)
```

## 鍵ペアの作成

```go
kp := keypair.NewSm2KeyPair()
// 暗号文形式を設定（オプション、デフォルトは C1C3C2）
kp.SetMode(keypair.C1C3C2)
// BouncyCastle・Java・大半の国密ゲートウェイと相互運用する場合は ASN.1 形式を使用
// kp.SetMode(keypair.ASN1C1C3C2)
// ウィンドウサイズを設定（オプション、デフォルトは 4、範囲 2-6）
kp.SetWindow(4)
```

### 鍵ペアの生成

```go
// SM2 鍵ペアを生成（256 ビット楕円曲線）
err := kp.GenKeyPair()
if err != nil {
    panic(err)
}

// PEM 形式の公開鍵を取得
publicKey := kp.PublicKey  
// PEM 形式の秘密鍵を取得
privateKey := kp.PrivateKey
```

### 既存 PEM 形式鍵から鍵ペアを設定

```go
// PEM 形式の公開鍵を設定
kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEv6TXzg5xkLbTkzQzmucCcGbVF1pv
BuOVxSa7tZEvT1bEKqF7WJx8UQ/a7R5YDslbMxPByZGqfPaeQEpwv3emQg==
-----END PUBLIC KEY-----`)

// PEM 形式の秘密鍵を設定
kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgsXklJOzFBfCXQGaP
5kVornBxt1WjgUIv21Imv7ALAtygCgYIKoEcz1UBgi2hRANCAAS/pNfODnGQttOT
NDOa5wJwZtUXWm8G45XFJru1kS9PVsQqoXtYnHxRD9rtHlgOyVszE8HJkap89p5A
SnC/d6ZC
-----END PRIVATE KEY-----`)
```

### 既存 DER 形式鍵から鍵ペアを設定

base64 エンコードされた DER に加えて、`SetPublicKey` / `SetPrivateKey` は hex でエンコードされた DER や生の鍵素材（公開鍵は 65 バイトの非圧縮点、秘密鍵は 32 バイトのスカラー）も受け取り、PEM に正規化します。

```go
// Base64 エンコードされた DER 形式公開鍵を設定
kp.SetPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEv6TXzg5xkLbTkzQzmucCcGbVF1pvBuOVxSa7tZEvT1bEKqF7WJx8UQ/a7R5YDslbMxPByZGqfPaeQEpwv3emQg=="))

// Base64 エンコードされた DER 形式秘密鍵を設定
kp.SetPrivateKey([]byte("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgsXklJOzFBfCXQGaP5kVornBxt1WjgUIv21Imv7ALAtygCgYIKoEcz1UBgi2hRANCAAS/pNfODnGQttOTNDOa5wJwZtUXWm8G45XFJru1kS9PVsQqoXtYnHxRD9rtHlgOyVszE8HJkap89p5ASnC/d6ZC"))
```

### `DER` 形式鍵を `PEM` 形式にフォーマット

```go
// base64 エンコードされた DER 形式公開鍵を PEM 形式にフォーマット
publicKey, err := kp.FormatPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEv6TXzg5xkLbTkzQzmucCcGbVF1pvBuOVxSa7tZEvT1bEKqF7WJx8UQ/a7R5YDslbMxPByZGqfPaeQEpwv3emQg=="))

// base64 エンコードされた DER 形式秘密鍵を PEM 形式にフォーマット
privateKey, err := kp.FormatPrivateKey([]byte("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgsXklJOzFBfCXQGaP5kVornBxt1WjgUIv21Imv7ALAtygCgYIKoEcz1UBgi2hRANCAAS/pNfODnGQttOTNDOa5wJwZtUXWm8G45XFJru1kS9PVsQqoXtYnHxRD9rtHlgOyVszE8HJkap89p5ASnC/d6ZC"))
```

### `PEM` 形式鍵を `DER` 形式に圧縮

```go
// PEM 形式公開鍵を base64 エンコードされた DER 形式に圧縮（PEM ブロックから base64 エンコードされた DER を抽出）
publicKey := kp.CompressPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEv6TXzg5xkLbTkzQzmucCcGbVF1pv
BuOVxSa7tZEvT1bEKqF7WJx8UQ/a7R5YDslbMxPByZGqfPaeQEpwv3emQg==
-----END PUBLIC KEY-----`))

// PEM 形式秘密鍵を base64 エンコードされた DER 形式に圧縮（PEM ブロックから base64 エンコードされた DER を抽出）
privateKey := kp.CompressPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgsXklJOzFBfCXQGaP
5kVornBxt1WjgUIv21Imv7ALAtygCgYIKoEcz1UBgi2hRANCAAS/pNfODnGQttOT
NDOa5wJwZtUXWm8G45XFJru1kS9PVsQqoXtYnHxRD9rtHlgOyVszE8HJkap89p5A
SnC/d6ZC
-----END PRIVATE KEY-----`))
```

> `CompressPublicKey` / `CompressPrivateKey` は `pem.Decode` で入力を解析するため、`Bag Attributes` などの任意のブロックヘッダーを含む PEM も処理できます。

## 公開鍵暗号化

> SM2 のストリーム暗号化は平文をすべて内部にバッファリングし、`Close` 時に一度だけ暗号化して出力します。

入力データ
```go
// 文字列を入力
encrypter := dongle.Encrypt.FromString("hello world").BySm2(kp)
// バイトスライスを入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm2(kp)
// ファイルストリームを入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm2(kp)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hex エンコード文字列を出力
hexString := encrypter.ToHexString() // 例：047fae94fd1a8b880d8d5454dd8df30c40...
// Hex エンコードバイトスライスを出力
hexBytes := encrypter.ToHexBytes()   // 例：[]byte("047fae94fd1a8b880d8d5454dd8df30c40...")

// Base64 エンコード文字列を出力
base64String := encrypter.ToBase64String() // 例：BH+ulP0ai4gNjVRU3Y3zDEA=...
// Base64 エンコードバイトスライスを出力
base64Bytes := encrypter.ToBase64Bytes()   // 例：[]byte("BH+ulP0ai4gNjVRU3Y3zDEA=...")

// エンコードされていない生の文字列を出力
rawString := encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
rawBytes := encrypter.ToRawBytes()  
```

## 秘密鍵復号化

入力データ
```go
// Hex エンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).BySm2(kp)
// Hex エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm2(kp)
// Hex エンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm2(kp)

// Base64 エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm2(kp)
// Base64 エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm2(kp)
// Base64 エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm2(kp)

// 生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).BySm2(kp)
// 生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm2(kp)
// 生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm2(kp)

// 復号化エラーをチェック
if decrypter.Error != nil {
	fmt.Printf("復号化エラー: %v\n", decrypter.Error)
	return
}
```

出力データ
```go
// 復号化された文字列を出力
decrypter.ToString() // hello world
// 復号化されたバイトスライスを出力
decrypter.ToBytes()  // []byte("hello world")
```