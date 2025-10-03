---
title: Hex エンコード/デコード
head:
  - - meta
    - name: description
      content: Hex エンコード/デコード | 軽量で意味的、開発者フレンドリーな golang エンコーディング&暗号化ライブラリ
  - - meta
    - name: keywords
      content: dongle, hex, base16
---

# Hex

Hex はバイナリデータを `ASCII` 文字にエンコードする方式で、`16` 個の文字（0-9, A-F）を使用してデータを表現します。`dongle` は標準およびストリーミング `Hex` エンコード、`Base16` エンコードとも呼ばれるものをサポートしています。

### データをエンコード
入力データ

```go
// 文字列を入力
encoder := dongle.Encode.FromString("hello world").ByHex()
// バイト配列を入力
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByHex()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByHex()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
encoder.ToString() // 68656c6c6f20776f726c64
// バイト配列を出力
encoder.ToBytes()  // []byte("68656c6c6f20776f726c64")
```

### データをデコード
入力データ

```go
// 文字列を入力
decoder := dongle.Decode.FromString("68656c6c6f20776f726c64").ByHex()
// バイト配列を入力
decoder := dongle.Decode.FromBytes([]byte("68656c6c6f20776f726c64")).ByHex()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByHex()

// デコードエラーをチェック
if decoder.Error != nil {
	fmt.Printf("デコードエラー: %v\n", decoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
decoder.ToString() // hello world
// バイト配列を出力
decoder.ToBytes()  // []byte("hello world")
```


