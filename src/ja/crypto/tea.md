---
title: TEA暗号化アルゴリズム
head:
  - - meta
    - name: description
      content: TEA暗号化アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: tea, 暗号化, 復号化, 対称暗号, ブロック暗号
---

# TEA

TEA（Tiny Encryption Algorithm）はシンプルで高効率なブロック暗号アルゴリズムで、固定長 `16` バイト鍵を使用してデータの暗号化と復号化を行います。`dongle` は標準およびストリーミング `TEA` 暗号化をサポートし、多様な入力形式、出力形式、ストリーム処理機能を提供します。

TEAは対称暗号化アルゴリズムで、暗号化と復号化で同じ鍵を使用します。TEAは `8` バイトのデータブロックで暗号化を行い、データ長は `8` の倍数でなければなりません。

注意事項

- **鍵長**：TEA鍵は `16` バイトでなければならない
- **データ長**：入力データ長は `8` バイトの倍数でなければならない
- **ラウンド数設定**：カスタムラウンド数をサポート、デフォルト `64` ラウンド、一般的な `32` ラウンドも使用
- **データアライメント**：データ長が `8` の倍数でない場合、手動でパディングが必要
- **セキュリティ**：TEAアルゴリズムは比較的シンプルで、パフォーマンス要求が高いがセキュリティ要求が極めて高くないシナリオに適合

関連モジュールをインポート：
```go
import (
    "github.com/dromara/dongle"
    "github.com/dromara/dongle/crypto/cipher"
)
```

## Cipherの作成

```go
c := cipher.NewTeaCipher()
// 鍵を設定（必ず16バイト）
c.SetKey([]byte("dongle1234567890"))
// ラウンド数を設定（オプション、デフォルト64ラウンド）
c.SetRounds(64)
```

## データの暗号化

入力データ

```go
// 入力文字列（必ず8バイトの倍数）
encrypter := dongle.Encrypt.FromString("12345678").ByTea(c)
// 入力バイトスライス（必ず8バイトの倍数）
encrypter := dongle.Encrypt.FromBytes([]byte("12345678")).ByTea(c)
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
hexString := encrypter.ToHexString() // a97fc8fdda9bebc7
// Hexエンコードバイトスライスを出力
hexBytes := encrypter.ToHexBytes()   // []byte("a97fc8fdda9bebc7")

// Base64エンコード文字列を出力
base64String := encrypter.ToBase64String() // qX/I/dqb68c=
// Base64エンコードバイトスライスを出力
base64Bytes := encrypter.ToBase64Bytes()   // []byte("qX/I/dqb68c=")

// エンコードなし生文字列を出力
rawString := encrypter.ToRawString()
// エンコードなし生バイトスライスを出力
rawBytes := encrypter.ToRawBytes()
```

## データの復号化

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

// エンコードなし生文字列を入力
decrypter := dongle.Decrypt.FromRawString(rawString).ByTea(c)
// エンコードなし生バイトスライスを入力
decrypter := dongle.Decrypt.FromRawBytes(rawBytes).ByTea(c)
// エンコードなし生ファイルストリームを入力
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
decrypter.ToString() // 12345678
// 復号化後のバイトスライスを出力
decrypter.ToBytes()  // []byte("12345678")
```