---
title: Base85エンコード/デコード
head:
  - - meta
    - name: description
      content: Base85エンコード/デコード | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: エンコード, デコード, base85, ascii85, base85-encoding, base85-decoding, ascii85-encoding, ascii85-decoding
---

# Base85

Base85は、バイナリデータを`ASCII`文字にエンコードする方法で、`85`文字（ASCII 33-117、つまり ! から u まで）を使用してデータを表現します。`dongle`は標準およびストリーミング`Base85`エンコードをサポートしており、`ASCII85`とも呼ばれ、`Adobe PostScript`および`PDF`仕様に準拠しています。

### データのエンコード
入力データ

```go
// 入力文字列
encoder := dongle.Encode.FromString("hello world").ByBase85()
// 入力バイトスライス
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase85()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase85()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 出力文字列
encoder.ToString() // BOu!rD]j7BEbo7
// 出力バイトスライス
encoder.ToBytes()  // []byte("BOu!rD]j7BEbo7")
```

### データのデコード
入力データ

```go
// 入力文字列
decoder := dongle.Decode.FromString("BOu!rD]j7BEbo7").ByBase85()
// 入力バイトスライス
decoder := dongle.Decode.FromBytes([]byte("BOu!rD]j7BEbo7")).ByBase85()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase85()

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

 