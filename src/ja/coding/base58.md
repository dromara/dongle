---
title: Base58エンコード/デコード
head:
  - - meta
    - name: description
      content: Base58 エンコード/デコード、ビットコインスタイルの文字セットに従い、混同しやすい文字（0、O、I、l）を除外、カスタムアルファベットをサポート、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、文字列とバイト出力を提供
  - - meta
    - name: keywords
      content: dongle, go-dongle, エンコード, デコード, Base58, ビットコインスタイル, アルファベット, カスタム文字セット, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, 文字列出力, バイト出力
---

# Base58

Base58は、バイナリデータを`ASCII`文字にエンコードする方法で、`58`文字（1-9、A-Z、a-z、混同しやすい文字 0、O、I、l を除く）を使用してデータを表現します。`dongle`は標準およびストリーミング`Base58`エンコードをサポートしており、ビットコインスタイルの仕様に従います。

> デフォルトのアルファベットは `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` です、
> `base58.StdAlphabet` を設定することでアルファベットをカスタマイズできます

### データのエンコード
入力データ

```go
// 入力文字列
encoder := dongle.Encode.FromString("hello world").ByBase58()
// 入力バイトスライス
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase58()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase58()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 出力文字列
encoder.ToString() // StV1DL6CwTryKyV
// 出力バイトスライス
encoder.ToBytes()  // []byte("StV1DL6CwTryKyV")
```

### データのデコード
入力データ

```go
// 入力文字列
decoder := dongle.Decode.FromString("StV1DL6CwTryKyV").ByBase58()
// 入力バイトスライス
decoder := dongle.Decode.FromBytes([]byte("StV1DL6CwTryKyV")).ByBase58()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase58()

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

 