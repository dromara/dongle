---
title: BLOWFISH暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: Blowfish 対称暗号化アルゴリズム。1〜56 バイトの可変長キーをサポートし、複数のブロックモード（CBC、ECB、CTR、CFB、OFB）とパディングモードを提供。標準処理とストリーム処理をサポートし、Hex および Base64 出力形式をサポートします
  - - meta
    - name: keywords
      content: dongle, go-dongle, 暗号化, 復号化, Blowfish, 対称暗号化アルゴリズム, ブロックモード, パディングモード, CBC, ECB, CTR, CFB, OFB
---

# Blowfish

Blowfishは対称暗号化アルゴリズムで、可変長の鍵をサポートし、鍵長は `1` から `56` バイトです。`dongle` は標準およびストリーミング `Blowfish` 暗号化をサポートし、多様なブロックモード、パディングモード、出力形式を提供します。

以下のブロックモードをサポート：

- **CBC（Cipher Block Chaining）**：暗号ブロック連鎖モード、鍵 `Key`、初期化ベクトル `IV`（8バイト）、パディングモード `Padding` の設定が必要
- **ECB（Electronic Codebook）**：電子暗号帳モード、鍵 `Key` とパディングモード `Padding` の設定が必要
- **CTR（Counter）**：カウンターモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要
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

### Cipherの作成
```go
c := cipher.NewBlowfishCipher(cipher.CBC)
// 鍵を設定（1-56バイト）
c.SetKey([]byte("12345678"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
// パディングモードを設定
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
encrypter.ToHexString() // f52a4cc3738f6ed0ee8fe4312fa9be82
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("f52a4cc3738f6ed0ee8fe4312fa9be82")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // 9SpMw3OPbtDuj+QxL6m+gg==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("9SpMw3OPbtDuj+QxL6m+gg==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
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
c.SetKey([]byte("12345678"))
// パディングモードを設定
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
encrypter.ToHexString() // 77caf7bc47a73ead1497a822dd1a2bf0
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("77caf7bc47a73ead1497a822dd1a2bf0")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // d8r3vEenPq0Ul6gi3Ror8A==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("d8r3vEenPq0Ul6gi3Ror8A==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
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

## CTRモード

### Cipherの作成

```go
c := cipher.NewBlowfishCipher(cipher.CTR)
// 鍵を設定（1-56バイト）
c.SetKey([]byte("12345678"))
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
encrypter.ToHexString() // 09f68045da3a38f2620280
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("09f68045da3a38f2620280")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // CfaARdo6OPJiAoA=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("CfaARdo6OPJiAoA=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
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

## CFBモード

> **注意**：CFBモードはCFB8実装を使用します。最初の16バイトのデータの場合、CFB8とOFBモードは同じ暗号化結果を生成します。これはGo標準ライブラリCFB8実装の特性であり、バグではありません。

### Cipherの作成

```go
c := cipher.NewBlowfishCipher(cipher.CFB)
// 鍵を設定（1-56バイト）
c.SetKey([]byte("12345678"))
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
encrypter.ToHexString() // 09f68045da3a38f217a836
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("09f68045da3a38f217a836")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // CfaARdo6OPIXqDY=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("CfaARdo6OPIXqDY=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
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

## OFBモード

> **注意**：CFBモードはCFB8実装を使用します。最初の16バイトのデータの場合、CFB8とOFBモードは同じ暗号化結果を生成します。これはGo標準ライブラリCFB8実装の特性であり、バグではありません。

### Cipherの作成

```go
c := cipher.NewBlowfishCipher(cipher.OFB)
// 鍵を設定（1-56バイト）
c.SetKey([]byte("12345678"))
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
encrypter.ToHexString() // 09f68045da3a38f2613a97
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("09f68045da3a38f2613a97")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // CfaARdo6OPJhOpc=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("CfaARdo6OPJhOpc=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
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
