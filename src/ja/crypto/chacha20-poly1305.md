---
title: ChaCha20-Poly1305暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: ChaCha20-Poly1305 認証暗号（AEAD）。32 バイト鍵と 12 バイトノンスをサポートし、追加認証データ（AAD）をサポート。パディングなしで任意の長さのデータを処理でき、標準処理とストリーム処理をサポートし、Hex および Base64 出力形式をサポートします
  - - meta
    - name: keywords
      content: dongle, go-dongle, 暗号化, 復号化, ChaCha20-Poly1305, ChaCha20, Poly1305, 対称暗号化アルゴリズム, ストリーム暗号, メッセージ認証コード, 認証暗号, AEAD
---

# ChaCha20-Poly1305

ChaCha20-Poly1305は、`ChaCha20`ストリーム暗号と`Poly1305`メッセージ認証コードを組み合わせた現代的な高性能認証付き暗号化アルゴリズム（AEAD）です。固定長の`32`バイト鍵と`12`バイト乱数を使用してデータを暗号化・認証します。`dongle`は標準およびストリーミング`ChaCha20-Poly1305`暗号化をサポートし、多様な入力形式、出力形式、ストリーム処理機能を提供します。

ChaCha20-Poly1305は対称暗号化アルゴリズムで、暗号化と復号化に同じ鍵を使用します。`AEAD`アルゴリズムとして、機密性保護だけでなく、完全性と真正性の検証も提供し、データの改ざんを検出できます。

注意事項

- **鍵長**：ChaCha20-Poly1305の鍵は`32`バイトである必要があります
- **乱数長**：ChaCha20-Poly1305の乱数は`12`バイトである必要があります
- **追加データ**：オプションの追加認証データ（AAD）、検証用ですが暗号化されません
- **認証タグ**：暗号化されたデータには`16`バイトの認証タグが含まれます
- **乱数の一意性**：各鍵の下で乱数は一意である必要があり、再利用できません
- **セキュリティ**：ChaCha20-Poly1305は高いセキュリティを提供し、`TLS1.3`などの標準で広く採用されています

関連モジュールをインポート：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Cipherの作成

```go
c := cipher.NewChaCha20Poly1305Cipher()
// 鍵を設定（32バイトである必要があります）
c.SetKey([]byte("dongle1234567890abcdef123456789x"))
// 乱数を設定（12バイトである必要があります）
c.SetNonce([]byte("123456789012"))
// 追加認証データを設定（オプション）
c.SetAAD([]byte("dongle"))
```

## データの暗号化

入力データ

```go
// 入力文字列
encrypter := dongle.Encrypt.FromString("hello world").ByChaCha20Poly1305(c)
// 入力バイトスライス
encrypter := dongle.Encrypt.FromBytes([]byte("hello world")).ByChaCha20Poly1305(c)
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encrypter := dongle.Encrypt.FromFile(file).ByChaCha20Poly1305(c)

// 暗号化エラーをチェック
if encrypter.Error != nil {
	fmt.Printf("暗号化エラー: %v\n", encrypter.Error)
	return
}
```

出力データ

```go
// Hex エンコードされた文字列を出力
hexString := encrypter.ToHexString() // 04457bd9e26e18b1975a89ed76e38bbddc6364721923967b10ca4c
// Hex エンコードされたバイトスライスを出力
hexBytes := encrypter.ToHexBytes()   // []byte("04457bd9e26e18b1975a89ed76e38bbddc6364721923967b10ca4c")

// Base64 エンコードされた文字列を出力
base64String := encrypter.ToBase64String() // BEV72eJuGLGXWontduOLvdxjZHIZI5Z7EMpM
// Base64 エンコードされたバイトスライスを出力
base64Bytes := encrypter.ToBase64Bytes()   // []byte("BEV72eJuGLGXWontduOLvdxjZHIZI5Z7EMpM")

// エンコードされていない生の文字列を出力
rawString := encrypter.ToRawString()
// エンコードされていない生のバイトスライスを出力
rawBytes := encrypter.ToRawBytes()
```

## データの復号化

入力データ

```go
// Hexエンコード文字列を入力
decrypter := dongle.Decrypt.FromHexString(hexString).ByChaCha20Poly1305(c)
// Hexエンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromHexBytes(hexBytes).ByChaCha20Poly1305(c)
// Hexエンコードファイルストリームを入力
file, _ := os.Open("encrypted.hex")
decrypter := dongle.Decrypt.FromHexFile(file).ByChaCha20Poly1305(c)

// Base64エンコード文字列を入力
decrypter := dongle.Decrypt.FromBase64String(base64String).ByChaCha20Poly1305(c)
// Base64エンコードバイトスライスを入力
decrypter := dongle.Decrypt.FromBase64Bytes(base64Bytes).ByChaCha20Poly1305(c)
// Base64エンコードファイルストリームを入力
file, _ := os.Open("encrypted.base64")
decrypter := dongle.Decrypt.FromBase64File(file).ByChaCha20Poly1305(c)

// エンコードされていない生の文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByChaCha20Poly1305(c)
// エンコードされていない生のバイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByChaCha20Poly1305(c)
// エンコードされていない生のファイルストリームを入力
file, _ := os.Open("encrypted.bin") 
decrypter := dongle.Decrypt.FromRawFile(file).ByChaCha20Poly1305(c)

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