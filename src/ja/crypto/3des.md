---
title: 3DES暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: 3DES暗号化アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: 暗号化, 復号化, TripleDES, 3DES, 対称暗号化アルゴリズム, ブロックモード, パディングモード, CBC, ECB, CTR, CFB, OFB
---

# 3DES

3DES（Triple Data Encryption Standard）は対称暗号化アルゴリズムで、`16` バイトまたは `24` バイトの鍵を使用します。`dongle` は標準およびストリーミング `3DES` 暗号化をサポートし、多様なブロックモード、パディングモード、出力形式を提供します。

以下のブロックモードをサポート：

- **CBC（Cipher Block Chaining）**：暗号ブロック連鎖モード、鍵 `Key`、初期化ベクトル `IV`（8バイト）、パディングモード `Padding` の設定が必要
- **CTR（Counter）**：カウンターモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要
- **ECB（Electronic Codebook）**：電子暗号帳モード、鍵 `Key` とパディングモード `Padding` の設定が必要
- **CFB（Cipher Feedback）**：暗号フィードバックモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要
- **OFB（Output Feedback）**：出力フィードバックモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要

> **注意**：`3DES` アルゴリズムは `GCM`（Galois/Counter Mode）モードをサポートしていません。これは `GCM` モードが `128` ビットブロックサイズの暗号アルゴリズムを必要とするのに対し、`3DES` は `64` ビットブロックサイズ（`8` バイト）しか持たないためです。これは暗号学標準の技術的制限であり、実装上の問題ではありません。

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

> **注意**：`CBC/ECB`ブロックモードのみパディングが必要です

関連モジュールのインポート：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## CBCモード

### Cipherの作成

```go
c := cipher.New3DesCipher(cipher.CBC)
// 鍵を設定（16バイトは自動的に24バイトに拡張）
c.SetKey([]byte("123456781234567812345678"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
// パディングモードを設定（オプション、デフォルトはPKCS7）
c.SetPadding(cipher.PKCS7) 
```

### データの暗号化

入力データ

```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
encrypter.ToHexBytes()  // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes()
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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
c := cipher.New3DesCipher(cipher.ECB)
// 鍵を設定（16バイトは自動的に24バイトに拡張）
c.SetKey([]byte("123456781234567812345678"))
// パディングモードを設定（オプション、デフォルトはPKCS7、CBC/ECBブロックモードのみパディングモードの設定が必要）
c.SetPadding(cipher.PKCS7)                   
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
encrypter.ToHexBytes()  // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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
c := cipher.New3DesCipher(cipher.CTR)
// 鍵を設定（16バイトは自動的に24バイトに拡張）
c.SetKey([]byte("123456781234567812345678"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321")) 
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
encrypter.ToHexBytes()  // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)

// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)

// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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

### Cipherの作成

```go
c := cipher.New3DesCipher(cipher.CFB)
// 鍵を設定（16バイトは自動的に24バイトに拡張）
c.SetKey([]byte("123456781234567812345678"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))                   
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
encrypter.ToHexBytes()  // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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

### Cipherの作成

```go
c := cipher.New3DesCipher(cipher.OFB)
// 鍵を設定（16バイトは自動的に24バイトに拡張）
c.SetKey([]byte("123456781234567812345678"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))                  
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").By3Des(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).By3Des(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).By3Des(c)

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
encrypter.ToHexBytes()  // []byte("7fae94fd1a8b880d8d5454dd8df30c40")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // f66U/RqLiA2NVFTdjfMMQA==
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("f66U/RqLiA2NVFTdjfMMQA==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).By3Des(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).By3Des(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).By3Des(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).By3Des(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).By3Des(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).By3Des(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).By3Des(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).By3Des(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).By3Des(c)

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
