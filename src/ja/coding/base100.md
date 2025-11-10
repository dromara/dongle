---
title: Base100エンコード/デコード
head:
  - - meta
    - name: description
      content: Base100 エンコード/デコード、Emoji 文字を使用して表現（各バイトを 4 バイト UTF-8 表情にマッピング）、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、文字列とバイト出力を提供
  - - meta
    - name: keywords
      content: dongle, go-dongle, エンコード, デコード, Base100, Emoji, UTF-8, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, 文字列出力, バイト出力
---

# Base100

Base100は、バイナリデータを`Emoji`文字にエンコードする方法で、各バイトを絵文字シンボルを表す`4バイト`の`UTF-8`シーケンスに変換します。`dongle`は標準およびストリーミング`Base100`エンコードをサポートしています。

### データのエンコード
入力データ

```go
// 入力文字列
encoder := dongle.Encode.FromString("hello world").ByBase100()
// 入力バイトスライス
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase100()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase100()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 出力文字列
encoder.ToString() // 👟👜👣👣👦🐗👮👦👩👣👛
// 出力バイトスライス
encoder.ToBytes()  // []byte("👟👜👣👣👦🐗👮👦👩👣👛")
```

### データのデコード
入力データ

```go
// 入力文字列
decoder := dongle.Decode.FromString("👟👜👣👣👦🐗👮👦👩👣👛").ByBase100()
// 入力バイトスライス
decoder := dongle.Decode.FromBytes([]byte("👟👜👣👣👦🐗👮👦👩👣👛")).ByBase100()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase100()

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

 