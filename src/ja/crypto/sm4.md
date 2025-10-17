---
title: SM4 対称暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: SM4 暗号化アルゴリズム|軽量で、意味が明確で、開発者にやさしい golang エンコード&暗号化ライブラリ
  - - meta
    - name: keywords
      content: 暗号化, 復号化, SM4, 対称暗号化アルゴリズム, 中国国家標準, ブロックモード, パディングモード, CBC, ECB, CTR, GCM, CFB, OFB
---

# SM4

`SM4`は対称暗号化アルゴリズムで、中国国家密码管理局が発表した商用対称ブロック暗号アルゴリズムであり、`16`バイトの鍵長をサポートしています。`dongle`は標準およびストリーミングの`SM4`暗号化をサポートし、複数のブロックモード、パディングモード、出力形式を提供します。

以下のブロックモードをサポートしています：

- **CBC（Cipher Block Chaining）**：暗号ブロックチェーンモード、鍵`Key`、初期化ベクトル`IV`（16バイト）、パディングモード`Padding`の設定が必要
- **ECB（Electronic Codebook）**：電子コードブックモード、鍵`Key`とパディングモード`Padding`の設定が必要
- **CTR（Counter）**：カウンターモード、鍵`Key`と初期化ベクトル`IV`（12バイト）の設定が必要
- **GCM（Galois/Counter Mode）**：ガロア/カウンターモード、鍵`Key`、ナンス`Nonce`（12バイト）、追加認証データ`AAD`（任意）の設定が必要
- **CFB（Cipher Feedback）**：暗号フィードバックモード、鍵`Key`と初期化ベクトル`IV`（16バイト）の設定が必要
- **OFB（Output Feedback）**：出力フィードバックモード、鍵`Key`と初期化ベクトル`IV`（16バイト）の設定が必要

以下のパディングモードをサポートしています：

- **No**：パディングなし、平文の長さは16の整数倍である必要があります
- **Zero**：ゼロパディング、ブロック境界までゼロバイトでパディング、平文の長さが16の倍数でない場合は0x00バイトでパディング
- **PKCS7**：PKCS#7パディング、最も一般的なパディング方式、N個の値がNのバイトでパディング、Nはパディングバイト数
- **PKCS5**：PKCS#5パディング、8バイトブロックサイズに適応、N個の値がNのバイトでパディング、Nはパディングバイト数
- **AnsiX923**：ANSI X.923パディング、最後のバイトを除きすべて0x00でパディング、最後のバイトはパディングバイト数を示す
- **ISO97971**：ISO/IEC 9797-1パディング、最初のバイトは0x80、残りは0x00でパディング
- **ISO10126**：ISO/IEC 10126パディング、最後のバイトを除きすべてランダムバイトでパディング、最後のバイトはパディングバイト数を示す
- **ISO78164**：ISO/IEC 7816-4パディング、最初のバイトは0x80、残りは0x00でパディング
- **Bit**：ビットパディング、平文の末尾に1ビットを追加し、ブロック境界まで0ビットでパディング

> **注意**：`CBC/ECB`ブロックモードのみパディングが必要です

関連モジュールのインポート：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## CBC モード

### Cipherの作成
```go
c := cipher.NewSm4Cipher(cipher.CBC)
// 鍵の設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルの設定（16バイト）
c.SetIV([]byte("1234567890123456"))
// パディングモードの設定（任意、デフォルトはPKCS7、CBC/ECBブロックモードのみパディングモードの設定が必要）
c.SetPadding(cipher.PKCS7)          
```

### データの暗号化

 入力データ

```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
    fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
    return
}
```

 出力データ

```go
// Hexエンコード文字列を出力
encrypter.ToHexString()
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()

// Base64エンコード文字列を出力
encrypter.ToBase64String()
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes()
```

### データの復号

 入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Hexエンコードファイル入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// 復号エラーのチェック
if decrypter.Error != nil {
    fmt.Printf("復号エラー: %v\n", decrypter.Error)
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

## ECB モード

### Cipherの作成

```go
c := cipher.NewSm4Cipher(cipher.ECB)
// 鍵の設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// パディングモードの設定（任意、デフォルトはPKCS7、CBC/ECBブロックモードのみパディングモードの設定が必要）
c.SetPadding(cipher.PKCS7) 
```

### データの暗号化

入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
    fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
    return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString()
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()

// Base64エンコード文字列を出力
encrypter.ToBase64String()
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号

入力データ
```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// 復号エラーのチェック
if decrypter.Error != nil {
    fmt.Printf("復号エラー: %v\n", decrypter.Error)
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

## CTR モード

### Cipherの作成

```go
c := cipher.NewSm4Cipher(cipher.CTR)
// 鍵の設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルの設定（12バイト）
c.SetIV([]byte("123456789012"))      
```

### データの暗号化

 入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
    fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
    return
}
```

 出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString()
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()

// Base64エンコード文字列を出力
encrypter.ToBase64String()
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号

 入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// 復号エラーのチェック
if decrypter.Error != nil {
    fmt.Printf("復号エラー: %v\n", decrypter.Error)
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

## GCM モード

GCMモードは認証暗号化機能を提供し、追加の認証データ（AAD）をサポートします。

### Cipherの作成

```go
c := cipher.NewSm4Cipher(cipher.GCM)
// 鍵の設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// ナンスの設定（12バイト）
c.SetNonce([]byte("123456789012"))
// 追加の認証データの設定（任意）
c.SetAAD([]byte("additional data")) 
```

### データの暗号化

 入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
    fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
    return
}
```

 出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString()
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()

// Base64エンコード文字列を出力
encrypter.ToBase64String()
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号

 入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// 復号エラーのチェック
if decrypter.Error != nil {
    fmt.Printf("復号エラー: %v\n", decrypter.Error)
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

## CFB モード

### Cipherの作成

```go
c := cipher.NewSm4Cipher(cipher.CFB)
// 鍵の設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルの設定（16バイト）
c.SetIV([]byte("1234567890123456"))  
```

### データの暗号化

 入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
    fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
    return
}
```

 出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString()
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()   

// Base64エンコード文字列を出力
encrypter.ToBase64String()
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()   

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号

 入力データ
```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// 復号エラーのチェック
if decrypter.Error != nil {
    fmt.Printf("復号エラー: %v\n", decrypter.Error)
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

## OFB モード

### Cipherの作成

```go
c := cipher.NewSm4Cipher(cipher.OFB)
// 鍵の設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルの設定（16バイト）
c.SetIV([]byte("1234567890123456"))  
```

### データの暗号化

 入力データ
```go
// 文字列入力
encrypter := dongle.Encrypt.FromString("hello world").BySm4(c)
// バイトスライス入力
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).BySm4(c)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).BySm4(c)

// 暗号化エラーのチェック
if encrypter.Error != nil {
    fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
    return
}
```

 出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString()
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()   

// Base64エンコード文字列を出力
encrypter.ToBase64String()
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()   

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号

 入力データ

```go
// Hexエンコード文字列入力
decrypter := dongle.Decrypt.FromHexString(hexString).BySm4(c)
// Hexエンコードバイトスライス入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).BySm4(c)
// Hexエンコードファイルストリーム入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).BySm4(c)

// Base64エンコード文字列入力
decrypter := dongle.Decrypt.FromBase64String(base64String).BySm4(c)
// Base64エンコードバイトスライス入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).BySm4(c)
// Base64エンコードファイルストリーム入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).BySm4(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).BySm4(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).BySm4(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).BySm4(c)

// 復号エラーのチェック
if decrypter.Error != nil {
    fmt.Printf("復号エラー: %v\n", decrypter.Error)
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