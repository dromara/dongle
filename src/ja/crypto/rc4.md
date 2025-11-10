---
title: RC4暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: RC4 (Rivest Cipher 4) ストリーム暗号化アルゴリズム、1-256 バイト可変長キーをサポート、パディングなしで任意の長さのデータを処理、標準処理とストリーム処理をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, 暗号化, 復号化, RC4, Rivest Cipher 4, 対称暗号化アルゴリズム, ストリーム暗号
---

# RC4

RC4（Rivest Cipher 4）はストリーム暗号化アルゴリズムで、可変長の鍵（1-256バイト）を使用してデータの暗号化と復号化を行います。`dongle` は標準およびストリーミング `RC4` 暗号化をサポートし、多様な入力形式、出力形式、ストリーム処理機能を提供します。

RC4は対称暗号化アルゴリズムで、暗号化と復号化で同じ鍵を使用します。RC4はストリーム暗号のため、パディングは不要で任意長のデータを直接処理できます。

関連モジュールをインポート：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Cipherの作成

```go
c := cipher.NewRc4Cipher()
// 鍵を設定（1-256バイト）
c.SetKey([]byte("dongle"))  
```

## データの暗号化
 入力データ

```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByRc4(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByRc4(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByRc4(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ
```go
// エンコードされていない生の文字列を出力
hexString := encrypter.ToHexString() // eba154b4cb5a9038dbbf9d
// エンコードされていない生のバイトスライスを出力
hexBytes := encrypter.ToHexBytes()   // []byte("eba154b4cb5a9038dbbf9d")

// エンコードされていない生の文字列を出力
base64String := encrypter.ToBase64String() // 66FUtMtakDjbv50=
// エンコードされていない生のバイトスライスを出力
base64Bytes := encrypter.ToBase64Bytes()   // []byte("66FUtMtakDjbv50=")

// エンコードされていない生の文字列を出力
rawString := encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
rawBytes := encrypter.ToRawBytes() 
```

## データの復号化

 入力データ
```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByRc4(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByRc4(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByRc4(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByRc4(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByRc4(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByRc4(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByRc4(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByRc4(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).ByRc4(c)

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