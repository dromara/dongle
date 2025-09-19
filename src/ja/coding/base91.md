---
title: Base91エンコード/デコード
head:
  - - meta
    - name: description
      content: Base91エンコード/デコード | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: dongle, base91
---

# Base91

Base91は、バイナリデータを`ASCII`文字にエンコードする方法で、`91`文字（A-Z、a-z、0-9、および特殊文字、スペース、アポストロフィ、ハイフン、バックスラッシュを除く）を使用してデータを表現します。`dongle`は標準的な`Base91`エンコードをサポートしています。

> デフォルトの文字セットは `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_{|}~"` です、
> `base91.StdAlphabet` を設定することで文字セットをカスタマイズできます

### データのエンコード

入力データ

```go
// 入力文字列
encoder := dongle.Encode.FromString("hello world").ByBase91()

// 入力バイトスライス
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase91()

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase91()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 出力文字列
encoder.ToString() // TPwJh>Io2Tv!lE
// 出力バイトスライス
encoder.ToBytes()  // []byte("TPwJh>Io2Tv!lE")
```

### データのデコード

入力データ

```go
// 入力文字列
decoder := dongle.Decode.FromString("TPwJh>Io2Tv!lE").ByBase91()

// 入力バイトスライス
decoder := dongle.Decode.FromBytes([]byte("TPwJh>Io2Tv!lE")).ByBase91()

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase91()

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

 