---
title: Unicode エンコード/デコード
head:
  - - meta
    - name: description
      content: Unicode エンコード/デコード、\uXXXX エスケープシーケンスを使用して非 ASCII 文字を表現、strconv.QuoteToASCII に基づいて実装、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、文字列とバイト出力を提供
  - - meta
    - name: keywords
      content: dongle, go-dongle, エンコード, デコード, Unicode, エスケープシーケンス, \uXXXX, ASCII, strconv.QuoteToASCII, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, 文字列出力, バイト出力
---

# Unicode

Unicode はバイトデータを `Unicode` エスケープシーケンスにエンコードする方式で、`\uXXXX` 形式を使用して非 `ASCII` 文字を表現します。`dongle` は標準およびストリーミング `Unicode` エンコード、`strconv.QuoteToASCII` に基づいて実装されたものをサポートしています。

### データをエンコード
入力データ

```go
// 文字列を入力
encoder := dongle.Encode.FromString("你好世界").ByUnicode()
// バイト配列を入力
encoder := dongle.Encode.FromBytes([]byte("你好世界")).ByUnicode()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByUnicode()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
encoder.ToString() // \u4f60\u597d\u4e16\u754c
// バイト配列を出力
encoder.ToBytes()  // []byte("\u4f60\u597d\u4e16\u754c")
```

### データをデコード
入力データ

```go
// 文字列を入力
decoder := dongle.Decode.FromString("\u4f60\u597d\u4e16\u754c").ByUnicode()
// バイト配列を入力
decoder := dongle.Decode.FromBytes([]byte("\u4f60\u597d\u4e16\u754c")).ByUnicode()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByUnicode()

// デコードエラーをチェック
if decoder.Error != nil {
	fmt.Printf("デコードエラー: %v\n", decoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
decoder.ToString() // 你好世界
// バイト配列を出力
decoder.ToBytes()  // []byte("你好世界")
```

