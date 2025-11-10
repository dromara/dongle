---
title: Hex エンコード/デコード
head:
  - - meta
    - name: description
      content: Hex エンコード/デコード、Base16 とも呼ばれ、16 個の文字（0-9, A-F）を使用、カスタム大文字小文字をサポート、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、文字列とバイト出力を提供
  - - meta
    - name: keywords
      content: dongle, go-dongle, エンコード, デコード, Hex, Base16, 大文字小文字, カスタム文字セット, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, 文字列出力, バイト出力
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


