---
title: Base45エンコード/デコード
head:
  - - meta
    - name: description
      content: Base45エンコード/デコード | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: dongle, base45
---

# Base45

Base45は、バイナリデータを`ASCII`文字にエンコードする方法で、`45`文字（0-9、A-Z、スペース、$、%、*、+、-、.、/、:）を使用してデータを表現します。`dongle`は標準的な`Base45`エンコードをサポートしており、`RFC9285`仕様に準拠しています。

> デフォルトのアルファベットは `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:` です、
> `base45.StdAlphabet` を設定することでアルファベットをカスタマイズできます

### データのエンコード

入力データ

```go
// 入力文字列
encoder := dongle.Encode.FromString("hello world").ByBase45()

// 入力バイトスライス
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase45()

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase45()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 出力文字列
encoder.ToString() // +8D VD82EK4F.KEA2
// 出力バイトスライス
encoder.ToBytes()  // []byte("+8D VD82EK4F.KEA2")
```

### データのデコード

入力データ

```go
// 入力文字列
decoder := dongle.Decode.FromString("+8D VD82EK4F.KEA2").ByBase45()

// 入力バイトスライス
decoder := dongle.Decode.FromBytes([]byte("+8D VD82EK4F.KEA2")).ByBase45()

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase45()

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