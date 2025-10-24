---
title: AES暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: AES暗号化アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: 暗号化, 復号化, AES, 対称暗号化アルゴリズム, ブロックモード, パディングモード, CBC, ECB, CTR, GCM, CFB, OFB
---

# AES

AES（Advanced Encryption Standard）は対称暗号化アルゴリズムで、`16` バイト、`24` バイト、`32` バイトの鍵長をサポートします。`dongle` は標準およびストリーミング `AES` 暗号化をサポートし、多様なブロックモード、パディングモード、出力形式を提供します。

以下のブロックモードをサポート：

- **CBC（Cipher Block Chaining）**：暗号ブロック連鎖モード、鍵 `Key`、初期化ベクトル `IV`（16バイト）、パディングモード `Padding` の設定が必要
- **ECB（Electronic Codebook）**：電子暗号帳モード、鍵 `Key` とパディングモード `Padding` の設定が必要
- **CTR（Counter）**：カウンターモード、鍵 `Key` と初期化ベクトル `IV`（12バイト）の設定が必要
- **GCM（Galois/Counter Mode）**：ガロア/カウンターモード、鍵 `Key`、乱数 `Nonce`（12バイト）、追加認証データ `AAD`（オプション）の設定が必要
- **CFB（Cipher Feedback）**：暗号フィードバックモード、鍵 `Key` と初期化ベクトル `IV`（16バイト）の設定が必要
- **OFB（Output Feedback）**：出力フィードバックモード、鍵 `Key` と初期化ベクトル `IV`（16バイト）の設定が必要

以下のパディングモードをサポート：

- **No**：パディングなし、平文長は16の倍数でなければならない
- **Zero**：ゼロパディング、ブロック境界までゼロバイトで埋める、平文長が16の倍数でない場合は0x00バイトで埋める
- **PKCS7**：PKCS#7パディング、最も一般的なパディング方式、Nバイトの値Nで埋める（Nはパディングバイト数）
- **PKCS5**：PKCS#5パディング、8バイトブロックサイズに適用、Nバイトの値Nで埋める（Nはパディングバイト数）
- **AnsiX923**：ANSI X.923パディング、最後のバイト以外は0x00で埋め、最後のバイトはパディングバイト数を表す
- **ISO97971**：ISO/IEC 9797-1パディング、最初のバイトは0x80、残りは0x00で埋める
- **ISO10126**：ISO/IEC 10126パディング、最後のバイト以外はランダムバイトで埋め、最後のバイトはパディングバイト数を表す
- **ISO78164**：ISO/IEC 7816-4パディング、最初のバイトは0x80、残りは0x00で埋める
- **Bit**：ビットパディング、平文末尾に1ビットを追加し、その後0ビットでブロック境界まで埋める
- **TBC**：末尾ビット補数パディング、最後のデータバイトの最上位ビットに基づいてパディングバイトを決定（MSB=0は0x00、MSB=1は0xFFを使用）

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
c := cipher.NewAesCipher(cipher.CBC)
// 鍵を設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルを設定（16バイト）
c.SetIV([]byte("1234567890123456"))
// パディングモードを設定（オプション、デフォルトはPKCS7、CBC/ECBブロックモードのみパディングモードの設定が必要）
c.SetPadding(cipher.PKCS7)          
```

### データの暗号化

入力データ

```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ

```go
// エンコードされていない生の文字列を出力
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// エンコードされていない生のバイトスライスを出力
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// エンコードされていない生の文字列を出力
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// エンコードされていない生のバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes()
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Hexエンコードファイルを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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
c := cipher.NewAesCipher(cipher.ECB)
// 鍵を設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// パディングモードを設定（オプション、デフォルトはPKCS7、CBC/ECBブロックモードのみパディングモードの設定が必要）
c.SetPadding(cipher.PKCS7) 
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// エンコードされていない生の文字列を出力
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// エンコードされていない生のバイトスライスを出力
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// エンコードされていない生の文字列を出力
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// エンコードされていない生のバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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
c := cipher.NewAesCipher(cipher.CTR)
// 鍵を設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルを設定（12バイト）
c.SetIV([]byte("123456789012"))      
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// エンコードされていない生の文字列を出力
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// エンコードされていない生のバイトスライスを出力
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// エンコードされていない生の文字列を出力
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// エンコードされていない生のバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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

## GCMモード

GCMモードは認証暗号化機能を提供し、追加認証データ（AAD）をサポートします。

### Cipherの作成

```go
c := cipher.NewAesCipher(cipher.GCM)
// 鍵を設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// 乱数を設定（12バイト）
c.SetNonce([]byte("123456789012"))
// 追加認証データを設定（オプション）
c.SetAAD([]byte("additional data")) 
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// エンコードされていない生の文字列を出力
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// エンコードされていない生のバイトスライスを出力
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// エンコードされていない生の文字列を出力
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// エンコードされていない生のバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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
c := cipher.NewAesCipher(cipher.CFB)
// 鍵を設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルを設定（16バイト）
c.SetIV([]byte("1234567890123456"))  
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// エンコードされていない生の文字列を出力
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// エンコードされていない生のバイトスライスを出力
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// エンコードされていない生の文字列を出力
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// エンコードされていない生のバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ
```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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
c := cipher.NewAesCipher(cipher.OFB)
// 鍵を設定（16バイト）
c.SetKey([]byte("dongle1234567890"))
// 初期化ベクトルを設定（16バイト）
c.SetIV([]byte("1234567890123456"))  
```

### データの暗号化

入力データ
```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByAes(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByAes(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByAes(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// エンコードされていない生の文字列を出力
encrypter.ToHexString() // 48c6bc076e1da2946e1c0e59e9c91ae9
// エンコードされていない生のバイトスライスを出力
encrypter.ToHexBytes()  // []byte("48c6bc076e1da2946e1c0e59e9c91ae9")

// エンコードされていない生の文字列を出力
encrypter.ToBase64String() // SMa8B24dopRuHA5Z6cka6Q==
// エンコードされていない生のバイトスライスを出力
encrypter.ToBase64Bytes()  // []byte("SMa8B24dopRuHA5Z6cka6Q==")

// エンコードされていない生の文字列を出力
encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
encrypter.ToRawBytes() 
```

### データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByAes(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByAes(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByAes(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByAes(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByAes(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByAes(c)

// 生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByAes(c)
// 生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByAes(c)
// 生ファイルストリームを入力
file, _ := os.Open("encrypted.bin")
decrypter := dongle.Decrypt.FromRawFile(file).ByAes(c)

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

