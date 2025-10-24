---
title: TEA暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: TEA暗号化アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: 暗号化, 復号化, TEA, 対称暗号化アルゴリズム, ブロックモード, パディングモード, CBC, ECB, CTR, CFB, OFB
---

# TEA

TEA（Tiny Encryption Algorithm）はシンプルで高効率なブロック暗号アルゴリズムで、固定長 `16` バイト鍵を使用してデータの暗号化と復号化を行います。`dongle` は標準およびストリーミング `TEA` 暗号化をサポートし、多様なブロックモード、パディングモード、出力形式を提供します。

サポートされているブロックモード：

- **CBC（Cipher Block Chaining）**：暗号ブロック連鎖モード、鍵 `Key`、初期化ベクトル `IV`（8バイト）、パディングモード `Padding` の設定が必要
- **ECB（Electronic Codebook）**：電子コードブックモード、鍵 `Key` とパディングモード `Padding` の設定が必要
- **CTR（Counter）**：カウンターモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要
- **CFB（Cipher Feedback）**：暗号フィードバックモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要
- **OFB（Output Feedback）**：出力フィードバックモード、鍵 `Key` と初期化ベクトル `IV`（8バイト）の設定が必要

> **注意**：TEAアルゴリズムは `GCM`（Galois/Counter Mode）モードをサポートしていません。これは `GCM` モードが暗号アルゴリズムに `128` ビットブロックサイズを要求するのに対し、`TEA` は `64` ビットブロックサイズ（`8` バイト）しか持たないためです。これは暗号学標準の技術的制限であり、実装の問題ではありません。

サポートされているパディングモード：

- **No**：パディングなし、平文長は8の倍数でなければならない
- **Zero**：ゼロパディング、ブロック境界までゼロバイトでパディング、平文長が8の倍数でない場合は0x00バイトでパディング
- **PKCS7**：PKCS#7パディング、最も一般的に使用されるパディング方式、N個の値Nのバイトでパディング、Nはパディングバイト数
- **PKCS5**：PKCS#5パディング、8バイトブロックサイズに適用、N個の値Nのバイトでパディング、Nはパディングバイト数
- **AnsiX923**：ANSI X.923パディング、最後のバイト以外は0x00でパディング、最後のバイトはパディングバイト数を示す
- **ISO97971**：ISO/IEC 9797-1パディング、最初のバイトは0x80、残りは0x00でパディング
- **ISO10126**：ISO/IEC 10126パディング、最後のバイト以外はランダムバイトでパディング、最後のバイトはパディングバイト数を示す
- **ISO78164**：ISO/IEC 7816-4パディング、最初のバイトは0x80、残りは0x00でパディング
- **Bit**：ビットパディング、平文末尾に1ビットを追加し、ブロック境界まで0ビットでパディング

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
c := cipher.NewTeaCipher(cipher.CBC)
// 鍵を設定（必ず16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
// パディングモードを設定（オプション、デフォルトはPKCS7、CBC/ECBブロックモードのみパディングモード設定が必要）
c.SetPadding(cipher.PKCS7)
// ラウンド数を設定（オプション、デフォルト64ラウンド）
c.SetRounds(64)
```

### データの暗号化

入力データ

```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTea(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ

```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // a97fc8fdda9bebc7
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("a97fc8fdda9bebc7")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // qX/I/dqb68c=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("qX/I/dqb68c=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes()
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTea(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTea(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTea(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTea(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTea(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTea(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTea(c)

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
c := cipher.NewTeaCipher(cipher.ECB)
// 鍵を設定（必ず16バイト）
c.SetKey([]byte("dongle1234567890"))
// パディングモードを設定（オプション、デフォルトはPKCS7、CBC/ECBブロックモードのみパディングモード設定が必要）
c.SetPadding(cipher.PKCS7)
// ラウンド数を設定（オプション、デフォルト64ラウンド）
c.SetRounds(64)
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTea(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // a97fc8fdda9bebc7
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("a97fc8fdda9bebc7")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // qX/I/dqb68c=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("qX/I/dqb68c=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTea(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTea(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTea(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTea(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTea(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTea(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)

// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)

// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTea(c)

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
c := cipher.NewTeaCipher(cipher.CTR)
// 鍵を設定（必ず16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
// ラウンド数を設定（オプション、デフォルト64ラウンド）
c.SetRounds(64)
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTea(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // a97fc8fdda9bebc7
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("a97fc8fdda9bebc7")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // qX/I/dqb68c=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("qX/I/dqb68c=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTea(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTea(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTea(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTea(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTea(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTea(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTea(c)

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
c := cipher.NewTeaCipher(cipher.CFB)
// 鍵を設定（必ず16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
// ラウンド数を設定（オプション、デフォルト64ラウンド）
c.SetRounds(64)
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTea(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // a97fc8fdda9bebc7
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("a97fc8fdda9bebc7")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // qX/I/dqb68c=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("qX/I/dqb68c=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTea(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTea(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTea(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTea(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTea(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTea(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTea(c)

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
c := cipher.NewTeaCipher(cipher.OFB)
// 鍵を設定（必ず16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルを設定（8バイト）
c.SetIV([]byte("87654321"))
// ラウンド数を設定（オプション、デフォルト64ラウンド）
c.SetRounds(64)
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByTea(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByTea(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByTea(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// Hexエンコード文字列を出力
encrypter.ToHexString() // a97fc8fdda9bebc7
// Hexエンコードバイトスライスを出力
encrypter.ToHexBytes()  // []byte("a97fc8fdda9bebc7")

// Base64エンコード文字列を出力
encrypter.ToBase64String() // qX/I/dqb68c=
// Base64エンコードバイトスライスを出力
encrypter.ToBase64Bytes()   // []byte("qX/I/dqb68c=")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByTea(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByTea(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByTea(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByTea(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByTea(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByTea(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByTea(c)

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