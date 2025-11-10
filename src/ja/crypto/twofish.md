---
title: Twofish 対称暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: Twofish 対称暗号化アルゴリズム。16、24、または 32 バイト鍵をサポートし、複数のブロックモード（CBC、ECB、CTR、GCM、CFB、OFB）とパディングモードを提供。標準処理とストリーム処理をサポートし、Hex および Base64 出力形式をサポートします
  - - meta
    - name: keywords
      content: dongle, go-dongle, 暗号化, 復号化, Twofish, 対称暗号化アルゴリズム, ブロックモード, パディングモード, CBC, ECB, CTR, GCM, CFB, OFB
---

# Twofish

Twofishは、`16`、`24`、または`32`バイトの固定長キーをサポートする対称暗号化アルゴリズムです。`dongle`は標準およびストリーミング`Twofish`暗号化をサポートし、複数のブロックモード、パディングモード、出力形式を提供します。

以下のブロックモードがサポートされています：

- **CBC（Cipher Block Chaining）**：暗号ブロック連鎖モード、キー`Key`、初期化ベクトル`IV`（16バイト）、パディングモード`Padding`の設定が必要
- **ECB（Electronic Codebook）**：電子コードブックモード、キー`Key`とパディングモード`Padding`の設定が必要
- **CTR（Counter）**：カウンターモード、キー`Key`と初期化ベクトル`IV`（16バイト）の設定が必要
- **GCM（Galois/Counter Mode）**：ガロアカウンターモード、キー`Key`、ナンス`Nonce`（1-255バイト）、オプションの追加認証データ`AAD`の設定が必要
- **CFB（Cipher Feedback）**：暗号フィードバックモード、キー`Key`と初期化ベクトル`IV`（16バイト）の設定が必要
- **OFB（Output Feedback）**：出力フィードバックモード、キー`Key`と初期化ベクトル`IV`（16バイト）の設定が必要

以下のパディングモードがサポートされています：

- **No**：パディングなし、平文の長さは16の倍数である必要があります
- **Zero**：ゼロパディング、ブロック境界までゼロバイトでパディング、平文の長さが16の倍数でない場合は0x00バイトでパディング
- **PKCS7**：PKCS#7パディング、最も一般的に使用されるパディング方式、N個の値Nのバイトでパディング、Nはパディングバイト数
- **PKCS5**：PKCS#5パディング、16バイトブロックサイズに適用、N個の値Nのバイトでパディング、Nはパディングバイト数
- **AnsiX923**：ANSI X.923パディング、最後のバイト以外を0x00でパディング、最後のバイトがパディングバイト数を示す
- **ISO97971**：ISO/IEC 9797-1パディング、最初のバイトが0x80、残りを0x00でパディング
- **ISO10126**：ISO/IEC 10126パディング、最後のバイト以外をランダムバイトでパディング、最後のバイトがパディングバイト数を示す
- **ISO78164**：ISO/IEC 7816-4パディング、最初のバイトが0x80、残りを0x00でパディング
- **Bit**：ビットパディング、平文の末尾に1ビットを追加し、ブロック境界まで0ビットでパディング
- **TBC**：末尾ビット補数パディング、最後のデータバイトの最上位ビットに基づいてパディングバイトを決定（MSB=0は0x00、MSB=1は0xFFを使用）

> **注意**：`CBC/ECB`ブロックモードのみパディングモードの設定が必要、`CBC/CTR/CFB/OFB`ブロックモードのみ初期化ベクトルの設定が必要

関連モジュールをインポート：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## CBCモード

### 暗号器の作成
```go
c := cipher.NewTwofishCipher(cipher.CBC)
// キーを設定（16、24、または32バイト）
c.SetKey([]byte("1234567890123456"))
// 初期化ベクトルを設定（16バイト）
c.SetIV([]byte("1234567890123456"))
// パディングモードを設定
c.SetPadding(cipher.PKCS7)
```

### データの暗号化

入力データ

```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ

```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 778e2e1e61afba198bb5128017cb4b81
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("778e2e1e61afba198bb5128017cb4b81")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // d44uHmGvuhmLtRKAF8tLgQ==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("d44uHmGvuhmLtRKAF8tLgQ==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes()
```

### データの復号化

入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

// 復号化エラーのチェック
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

## ECBモード

### 暗号器の作成

```go
c := cipher.NewTwofishCipher(cipher.ECB)
// キーを設定（16、24、または32バイト）
c.SetKey([]byte("1234567890123456"))
// パディングモードを設定
c.SetPadding(cipher.PKCS7)
```

### データの暗号化

入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 0fb94e36c8a2f1c2f66994638121d2c8
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("0fb94e36c8a2f1c2f66994638121d2c8")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // D7lONsii8cL2aZRjgSHSyA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("D7lONsii8cL2aZRjgSHSyA==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

// 復号化エラーのチェック
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

## CTRモード

### 暗号器の作成

```go
c := cipher.NewTwofishCipher(cipher.CTR)
// キーを設定（16、24、または32バイト）
c.SetKey([]byte("1234567890123456"))
// 初期化ベクトルを設定（16バイト）
c.SetIV([]byte("1234567890123456"))
```

### データの暗号化

入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 7cd470bfd6d8e18b57d269
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("7cd470bfd6d8e18b57d269")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // fNRwv9bY4YtX0mk=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("fNRwv9bY4YtX0mk=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)

// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)

// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

// 復号化エラーのチェック
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

## CFBモード

> **注意**：CFBモードはCFB8実装を使用します。最初の16バイトのデータの場合、CFB8とOFBモードは同じ暗号化結果を生成します。これはGo標準ライブラリCFB8実装の特性であり、バグではありません。

### 暗号器の作成

```go
c := cipher.NewTwofishCipher(cipher.CFB)
// キーを設定（16、24、または32バイト）
c.SetKey([]byte("1234567890123456"))
// 初期化ベクトルを設定（16バイト）
c.SetIV([]byte("1234567890123456"))
```

### データの暗号化

入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 7cd470bfd6d8e18b57d269
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("7cd470bfd6d8e18b57d269")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // fNRwv9bY4YtX0mk=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("fNRwv9bY4YtX0mk=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

// 復号化エラーのチェック
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

## OFBモード

> **注意**：CFBモードはCFB8実装を使用します。最初の16バイトのデータの場合、CFB8とOFBモードは同じ暗号化結果を生成します。これはGo標準ライブラリCFB8実装の特性であり、バグではありません。

### 暗号器の作成

```go
c := cipher.NewTwofishCipher(cipher.OFB)
// キーを設定（16、24、または32バイト）
c.SetKey([]byte("1234567890123456"))
// 初期化ベクトルを設定（16バイト）
c.SetIV([]byte("1234567890123456"))
```

### データの暗号化

入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 7cd470bfd6d8e18b57d269
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("7cd470bfd6d8e18b57d269")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // fNRwv9bY4YtX0mk=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("fNRwv9bY4YtX0mk=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

// 復号化エラーのチェック
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

## GCMモード

### 暗号器の作成

```go
c := cipher.NewTwofishCipher(cipher.GCM)
// キーを設定（16、24、または32バイト）
c.SetKey([]byte("1234567890123456"))
// ナンスを設定（1-255バイト）
c.SetNonce([]byte("12345678"))
// 追加認証データを設定（オプション）
c.SetAAD([]byte("dongle"))
```

### データの暗号化

入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").ByTwofish(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTwofish(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTwofish(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // 36059dc3fbbc82418a032f74ae9ffa55077aa925f61a1a16eb0dd0
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("36059dc3fbbc82418a032f74ae9ffa55077aa925f61a1a16eb0dd0")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // NgWdw/u8gkGKAy90rp/6VQd6qSX2GhoW6w3Q
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("NgWdw/u8gkGKAy90rp/6VQd6qSX2GhoW6w3Q")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTwofish(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTwofish(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTwofish(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTwofish(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTwofish(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTwofish(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTwofish(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTwofish(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTwofish(c)

// 復号化エラーのチェック
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