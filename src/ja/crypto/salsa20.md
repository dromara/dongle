---
title: Salsa20 流密码暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: Salsa20 ストリーム暗号化アルゴリズム。32 バイト鍵と 8 バイトノンスをサポートし、パディングなしで任意の長さのデータを処理。標準処理とストリーム処理をサポートし、Hex および Base64 出力形式をサポートします
  - - meta
    - name: keywords
      content: dongle, go-dongle, 暗号化, 復号化, Salsa20, 対称暗号化アルゴリズム, ストリーム暗号, ノンス, ストリーム処理, Hex, Base64
---

# Salsa20

Salsa20 は、固定長の `32` バイトキーと `8` バイトナンスを使用してデータを暗号化・復号化する現代の高性能ストリーム暗号アルゴリズムです。`dongle` は標準およびストリーミング `Salsa20` 暗号化をサポートし、複数の入力形式、出力形式、ストリーミング機能を提供します。

Salsa20 は暗号化と復号化に同じキーを使用する対称暗号アルゴリズムです。ストリーム暗号として、Salsa20 はデータの整列要件なしに任意の長さのデータを処理できます。

## 注意事項

- **キー長**: Salsa20 キーは `32` バイトである必要があります
- **ナンス長**: Salsa20 ナンスは `8` バイトである必要があります
- **データ長**: 整列要件なしに任意の長さのデータをサポート
- **ナンスの一意性**: 各キー下のナンスは一意でなければならず、再利用できません
- **セキュリティ**: Salsa20 は高いセキュリティを提供し、現代の暗号アプリケーションで広く使用されています

関連モジュールをインポート:
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Cipher の作成

```go
c := cipher.NewSalsa20Cipher()
// キーを設定（32 バイトである必要があります）
c.SetKey([]byte("dongle1234567890abcdef123456789x"))
// ナンスを設定（8 バイトである必要があります）
c.SetNonce([]byte("12345678"))
```

## データの暗号化

### 入力データ

```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").BySalsa20(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySalsa20(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySalsa20(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

### 出力データ

```go
// Hex エンコード文字列を出力
hexString := encrypter.ToHexString() // 39ee99ffc157388ef95814
// Hex エンコードバイトスライスを出力
hexBytes := encrypter.ToHexBytes()   // []byte("39ee99ffc157388ef95814")

// Base64 エンコード文字列を出力
base64String := encrypter.ToBase64String() // Oe6Z/8FXOI75WBQ=
// Base64 エンコードバイトスライスを出力
base64Bytes := encrypter.ToBase64Bytes()   // []byte("Oe6Z/8FXOI75WBQ=")

// エンコードされていない生の文字列を出力
rawString := encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
rawBytes := encrypter.ToRawBytes()
```

## データの復号化

### 入力データ

```go
// Hex エンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).BySalsa20(c)
// Hex エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySalsa20(c)
// Hex エンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySalsa20(c)

// Base64 エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).BySalsa20(c)
// Base64 エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySalsa20(c)
// Base64 エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySalsa20(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).BySalsa20(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySalsa20(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).BySalsa20(c)

// 復号化エラーのチェック
if decrypter.Error != nil {
	fmt.Printf("復号化エラー: %v\n", decrypter.Error)
	return
}
```

### 出力データ

```go
// 復号化後の文字列を出力
decrypter.ToString() // hello world
// 復号化後のバイトスライスを出力
decrypter.ToBytes()  // []byte("hello world")
```
