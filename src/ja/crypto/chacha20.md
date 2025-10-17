---
title: ChaCha20暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: ChaCha20暗号化アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: 暗号化, 復号化, ChaCha20, 対称暗号化アルゴリズム, 流密码
---

# ChaCha20

ChaCha20は現代的な高性能ストリーム暗号アルゴリズムで、固定長の `32` バイト鍵と `12` バイト乱数を使用してデータの暗号化と復号化を行います。`dongle` は標準およびストリーミング `ChaCha20` 暗号化をサポートし、多様な入力形式、出力形式、ストリーム処理機能を提供します。

ChaCha20は対称暗号化アルゴリズムで、暗号化と復号化で同じ鍵を使用します。ChaCha20はストリーム暗号として任意長のデータを処理でき、データアライメント要件はありません。

 注意事項

- **鍵長**：ChaCha20の鍵は `32` バイトでなければならない
- **乱数長**：ChaCha20の乱数は `12` バイトでなければならない
- **データ長**：任意長のデータをサポート、アライメント要件なし
- **乱数の一意性**：各鍵における乱数は一意でなければならず、再使用不可
- **セキュリティ**：ChaCha20は高いセキュリティを提供し、現代の暗号化アプリケーションで広く使用されている

関連モジュールをインポート：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Cipherの作成

```go
c := cipher.NewChaCha20Cipher()
// 鍵を設定（32バイト必須）
c.SetKey([]byte("dongle1234567890abcdef123456789x"))
// 乱数を設定（12バイト必須）
c.SetNonce([]byte("123456789012"))
```

## データの暗号化

 入力データ

```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByChaCha20(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByChaCha20(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByChaCha20(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

 出力データ

```go
// エンコードされていない生の文字列を出力
hexString := encrypter.ToHexString() // 4a1c8f2d3e5a6b7c
// エンコードされていない生のバイトスライスを出力
hexBytes := encrypter.ToHexBytes()   // []byte("4a1c8f2d3e5a6b7c")

// エンコードされていない生の文字列を出力
base64String := encrypter.ToBase64String() // ShyPLT5aa3w=
// エンコードされていない生のバイトスライスを出力
base64Bytes := encrypter.ToBase64Bytes()   // []byte("ShyPLT5aa3w=")

// エンコードされていない生の文字列を出力
rawString := encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
rawBytes := encrypter.ToRawBytes()
```

## データの復号化

 入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByChaCha20(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByChaCha20(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByChaCha20(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByChaCha20(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByChaCha20(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByChaCha20(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByChaCha20(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByChaCha20(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).ByChaCha20(c)

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