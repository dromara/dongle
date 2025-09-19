---
title: Base62エンコード/デコード
head:
  - - meta
    - name: description
      content: Base62エンコード/デコード | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: dongle, base62
---

# Base62

Base62は、バイナリデータを`ASCII`文字にエンコードする方法で、`62`文字（0-9、A-Z、a-z）を使用してデータを表現します。`dongle`は標準的な`Base62`エンコードをサポートしています。

> デフォルトのアルファベットは `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` です、
> `base62.StdAlphabet` を設定することでアルファベットをカスタマイズできます

### データのエンコード

入力データ

```go
// 入力文字列
encoder := dongle.Encode.FromString("hello world").ByBase62()

// 入力バイトスライス
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase62()

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase62()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 出力文字列
encoder.ToString() // AAwf93rvy4aWQVw
// 出力バイトスライス
encoder.ToBytes()  // []byte("AAwf93rvy4aWQVw")
```

### データのデコード

入力データ

```go
// 入力文字列
decoder := dongle.Decode.FromString("AAwf93rvy4aWQVw").ByBase62()

// 入力バイトスライス
decoder := dongle.Decode.FromBytes([]byte("AAwf93rvy4aWQVw")).ByBase62()

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase62()

// デコードエラーをチェック
if decoder.Error != nil {
	fmt.Printf("デコードエラー: %v\n", decoder.Error)
	return
}
```

出力データ

```go
// 出力文字列
decoder.ToString() // hello world
// 出力バイトスライス
decoder.ToBytes()  // []byte("hello world")
```

 