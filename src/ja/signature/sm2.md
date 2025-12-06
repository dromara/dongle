---
title: SM2 デジタル署名アルゴリズム
head:
  - - meta
    - name: description
      content: SM2 デジタル署名アルゴリズム、中国国家暗号管理局が制定した国産商用暗号アルゴリズム、楕円曲線暗号に基づき、秘密鍵で署名、公開鍵で検証を使用、標準およびストリーム処理をサポート、Hex と Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, 署名, 検証, SM2, デジタル署名アルゴリズム, 非対称暗号化, 楕円曲線, 秘密鍵署名, 公開鍵検証, 国密アルゴリズム, PKCS8, SPKI, UID, SM3
---

# SM2

SM2 は中国国家暗号管理局が制定した楕円曲線公開鍵暗号アルゴリズム（GM/T 0003-2012）であり、中国の商用暗号標準の中核アルゴリズムの一つです。`dongle` は標準およびストリーム `SM2` デジタル署名をサポートし、GM/T 0009-2012 標準に準拠した署名および検証機能を提供します。

SM2 署名アルゴリズムの特徴：

- **国密標準**：GM/T 0009-2012 デジタル署名標準に完全準拠
- **高いセキュリティ**：256 ビット楕円曲線を使用し、RSA 3072 ビットに相当するセキュリティ強度を提供
- **ユーザー識別子**：カスタム UID（ユーザー識別子）をサポート、デフォルトは `"1234567812345678"`
- **ハッシュアルゴリズム**：メッセージダイジェストに SM3 ハッシュアルゴリズムを内蔵使用
- **署名形式**：ASN.1 DER 形式で署名を保存（標準形式）
- **パフォーマンス最適化**：ウィンドウサイズ最適化をサポートし、署名および検証のパフォーマンスを向上

注意事項：

- **鍵形式**：秘密鍵は `PKCS#8` 形式で保存、公開鍵は `SPKI/PKIX` 形式で保存
- **UID の一貫性**：署名と検証は同じ UID を使用する必要があります。そうでない場合、検証は失敗します
- **デフォルト UID**：UID が設定されていない場合、デフォルト値 `"1234567812345678"` が使用されます（GM/T 0009-2012 に準拠）
- **秘密鍵のセキュリティ**：秘密鍵は適切に保管し、漏洩してはいけません。秘密鍵の保持者のみが有効な署名を生成できます
- **署名検証**：誰でも公開鍵を使用して署名の有効性を検証できます
- **標準準拠**：GM/T 0009-2012（デジタル署名アルゴリズム）標準に完全準拠

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
// ユーザー識別子 UID を設定（オプション、デフォルトは "1234567812345678"）
kp.SetUID([]byte("user@example.com"))
// ウィンドウサイズを設定（オプション、デフォルトは 4、範囲 2-6、パフォーマンス最適化用）
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
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXy
RHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA==
-----END PUBLIC KEY-----`)

// PEM 形式の秘密鍵を設定
kp.PrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5
u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJE
crAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg
-----END PRIVATE KEY-----`)
```

### 既存 DER 形式鍵から鍵ペアを設定

```go
// Base64 エンコードされた DER 形式公開鍵を設定
kp.SetPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXyRHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA=="))

// Base64 エンコードされた DER 形式秘密鍵を設定
kp.SetPrivateKey([]byte("MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJEcrAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg"))
```

### `DER` 形式鍵を `PEM` 形式にフォーマット

```go
// base64 エンコードされた DER 形式公開鍵を PEM 形式にフォーマット
publicKey, err := kp.FormatPublicKey([]byte("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXyRHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA=="))

// base64 エンコードされた DER 形式秘密鍵を PEM 形式にフォーマット
privateKey, err := kp.FormatPrivateKey([]byte("MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJEcrAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg"))
```

### `PEM` 形式鍵を `DER` 形式に圧縮

```go
// PEM 形式公開鍵を base64 エンコードされた DER 形式に圧縮（PEM 形式のヘッダー/フッターと改行を削除）
publicKey, err := kp.CompressPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEVJKqUmu59VTLhqCiVBmKqRjL5MXy
RHKwFAI+qG2Hqy5Wf5cLRlIf7aSMKqwGvYpP6gVOqQpvBdDQhDqr8rqrYA==
-----END PUBLIC KEY-----`))

// PEM 形式秘密鍵を base64 エンコードされた DER 形式に圧縮（PEM 形式のヘッダー/フッターと改行を削除）
privateKey, err := kp.CompressPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKvp8GZUkqT8UH/Z5
u8mjNM0JIvqmFolR6LczGEZmSvmhRANCAARUkqpSa7n1VMuGoKJUGYqpGMvkxfJE
crAUAj6obYerLlZ/lwtGUh/tpIwqrAa9ik/qBU6pCm8F0NCEOqvyuqtg
-----END PRIVATE KEY-----`))
```

## 秘密鍵署名

### 入力データ

```go
// 文字列を入力
signer := dongle.Sign.FromString("hello world").BySm2(kp)
// バイトスライスを入力
signer := dongle.Sign.FromBytes([]byte("hello world")).BySm2(kp)
// ファイルストリームを入力
file, _ := os.Open("test.txt")
signer := dongle.Sign.FromFile(file).BySm2(kp)

// 署名エラーをチェック
if signer.Error != nil {
	fmt.Printf("署名エラー: %v\n", signer.Error)
	return
}
```

### 出力データ

```go
// Hex エンコード署名文字列を出力
hexString := signer.ToHexString() // 例：3045022100a1b2c3d4e5f6...
// Hex エンコード署名バイトスライスを出力
hexBytes := signer.ToHexBytes()   // 例：[]byte("3045022100a1b2c3d4e5f6...")

// Base64 エンコード署名文字列を出力
base64String := signer.ToBase64String() // 例：MEUCIQCobLPeVv...
// Base64 エンコード署名バイトスライスを出力
base64Bytes := signer.ToBase64Bytes()   // 例：[]byte("MEUCIQCobLPeVv...")

// エンコードされていない生の署名文字列を出力
rawString := signer.ToRawString()
// エンコードされていない生の署名バイトスライスを出力
rawBytes := signer.ToRawBytes()
```

## 公開鍵検証

> 注意：`WithXxxSign` メソッドは `BySm2` の前に呼び出す必要があります

### 入力データ

```go
// 文字列を入力
verifier := dongle.Verify.FromString("hello world")
// バイトスライスを入力
verifier := dongle.Verify.FromBytes([]byte("hello world"))
// ファイルストリームを入力
file, _ := os.Open("test.txt")
verifier := dongle.Verify.FromFile(file)

// Hex エンコード署名を設定
verifier.WithHexSign(hexBytes).BySm2(kp)
// Base64 エンコード署名を設定
verifier.WithBase64Sign(base64Bytes).BySm2(kp)
// エンコードされていない生の署名を設定
verifier.WithRawSign(rawBytes).BySm2(kp)

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
