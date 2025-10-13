---
title: BLOWFISH暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: BLOWFISH暗号化アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: blowfish, 暗号化, 復号化, 対称暗号, ブロック暗号
---

# Blowfish

Blowfishは対称暗号化アルゴリズムで、可変長の鍵をサポートし、鍵長は `1` から `56` バイトです。`dongle` は標準およびストリーミング `Blowfish` 暗号化をサポートし、多様なブロックモード、パディングモード、出力形式を提供します。

以下のブロックモードをサポート：

- **CBC（Cipher Block Chaining）**：暗号ブロック連鎖モード、鍵 `Key`、初期化ベクトル `IV`（8バイト）、パディングモード `Padding` の設定が必要
- **CTR（Counter）**：カウンターモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要
- **ECB（Electronic Codebook）**：電子暗号帳モード、鍵 `Key` とパディングモード `Padding` の設定が必要
- **CFB（Cipher Feedback）**：暗号フィードバックモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要
- **OFB（Output Feedback）**：出力フィードバックモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要

> **注意**：`Blowfish` アルゴリズムは `GCM`（Galois/Counter Mode）モードをサポートしていません。これは `GCM` モードが `128` ビットブロックサイズの暗号アルゴリズムを必要とするのに対し、`Blowfish` は `64` ビットブロックサイズ（`8` バイト）しか持たないためです。これは暗号学標準の技術的制限であり、実装上の問題ではありません。

以下のパディングモードをサポート：

- **No**：パディングなし、平文長は8の倍数でなければならない
- **Zero**：ゼロパディング、ブロック境界までゼロバイトで埋める、平文長が8の倍数でない場合は0x00バイトで埋める
- **PKCS7**：PKCS#7パディング、最も一般的なパディング方式、Nバイトの値Nで埋める（Nはパディングバイト数）
- **PKCS5**：PKCS#5パディング、8バイトブロックサイズに適用、Nバイトの値Nで埋める（Nはパディングバイト数）
- **AnsiX923**：ANSI X.923パディング、最後のバイト以外は0x00で埋め、最後のバイトはパディングバイト数を表す
- **ISO97971**：ISO/IEC 9797-1パディング、最初のバイトは0x80、残りは0x00で埋める
- **ISO10126**：ISO/IEC 10126パディング、最後のバイト以外はランダムバイトで埋め、最後のバイトはパディングバイト数を表す
- **ISO78164**：ISO/IEC 7816-4パディング、最初のバイトは0x80、残りは0x00で埋める
- **Bit**：ビットパディング、平文末尾に1ビットを追加し、その後0ビットでブロック境界まで埋める

> **注意**：`CBC/ECB`ブロックモードのみパディングが必要です

関連モジュールをインポート：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## CBCモード

### Cipherの作成
```go
c := cipher.NewBlowfishCipher(cipher.CBC)
// 鍵を設定（1-56バイト）
c.SetKey([]byte("1234567890123456"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
// パディングモードを設定（オプション、デフォルトはPKCS7）
c.SetPadding(cipher.PKCS7)
```

### データの暗号化

入力データ

```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ

```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードなし生文字列を出力
encrypter.ToRawString()
// エンコードなし生バイトスライスを出力
encrypter.ToRawBytes()
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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
decrypter.ToBytes()  // []byte("hello world")
```

## ECBモード

### Cipherの作成

```go
c := cipher.NewBlowfishCipher(cipher.ECB)
// 鍵を設定（1-56バイト）
c.SetKey([]byte("1234567890123456"))
// パディングモードを設定（オプション、デフォルトはPKCS7、CBC/ECBブロックモードのみパディングモードの設定が必要）
c.SetPadding(cipher.PKCS7)
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードなし生文字列を出力
encrypter.ToRawString()
// エンコードなし生バイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

// 復号化エラーをチェック
if decrypter.Error != nil {
	fmt.Printf("復号化エラー: %v\n", decrypter.Error)
	return
}
```

出力データ

```go
// 文字列を出力
decrypter.ToString() // hello world
// バイトスライスを出力
decrypter.ToBytes()  // []byte("hello world")
```

## CTRモード

### Cipherの作成

```go
c := cipher.NewBlowfishCipher(cipher.CTR)
// 鍵を設定（1-56バイト）
c.SetKey([]byte("1234567890123456"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードなし生文字列を出力
encrypter.ToRawString()
// エンコードなし生バイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ
```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

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

## CFBモード

### Cipherの作成

```go
c := cipher.NewBlowfishCipher(cipher.CFB)
// 鍵を設定（1-56バイト）
c.SetKey([]byte("1234567890123456"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードなし生文字列を出力
encrypter.ToRawString()
// エンコードなし生バイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

// 復号化エラーをチェック
if decrypter.Error != nil {
	fmt.Printf("復号化エラー: %v\n", decrypter.Error)
	return
}
```

出力データ

```go
// 文字列を出力
decrypter.ToString() // hello world
// バイトスライスを出力
decrypter.ToBytes() // []byte("hello world")
```

## OFBモード

### Cipherの作成

```go
c := cipher.NewBlowfishCipher(cipher.OFB)
// 鍵を設定（1-56バイト）
c.SetKey([]byte("1234567890123456"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByBlowfish(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByBlowfish(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByBlowfish(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 7fae94fd1a8b880d8d5454dd8df30c40
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()   // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()   // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードなし生文字列を出力
encrypter.ToRawString()
// エンコードなし生バイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByBlowfish(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByBlowfish(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByBlowfish(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByBlowfish(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByBlowfish(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByBlowfish(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByBlowfish(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByBlowfish(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByBlowfish(c)

// 復号化エラーをチェック
if decrypter.Error != nil {
	fmt.Printf("復号化エラー: %v\n", decrypter.Error)
	return
}
```

出力データ

```go
// 文字列を出力
decrypter.ToString() // hello world
// バイトスライスを出力
decrypter.ToBytes() // []byte("hello world")
```
