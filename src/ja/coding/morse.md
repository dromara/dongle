---
title: Morse エンコード/デコード
head:
  - - meta
    - name: description
      content: Morse エンコード/デコード | 軽量で意味的、開発者フレンドリーな golang エンコーディング&暗号化ライブラリ
  - - meta
    - name: keywords
      content: エンコード, デコード, morse, モールス信号, モールス符号, morse-encoding, morse-decoding
---

# Morse

Morse はテキストを点と線のシーケンスにエンコードする方式で、国際モールス信号標準（ITU-R M.1677-1）に従います。`dongle` は標準およびストリーミング `Morse` エンコードをサポートし、文字、数字、句読点を標準化された点と線のシーケンスに変換します。
> デフォルトの区切り文字は`スペース`、
> `morse.StdSeparator` を設定して区切り文字をカスタマイズできます

### データをエンコード

```go
// 文字列を入力
encoder := dongle.Encode.FromString("hello world").ByMorse()
// バイト配列を入力
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByMorse()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByMorse()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
encoder.ToString() // .... . .-.. .-.. --- / .-- --- .-. .-.. -..
// バイト配列を出力
encoder.ToBytes()  // []byte(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")
```

### データをデコード
入力データ

```go
// 文字列を入力
decoder := dongle.Decode.FromString(".... . .-.. .-.. --- / .-- --- .-. .-.. -..").ByMorse()
// バイト配列を入力
decoder := dongle.Decode.FromBytes([]byte(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")).ByMorse()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByMorse()

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


