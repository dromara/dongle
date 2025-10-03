---
title: Base32 エンコード/デコード
head:
  - - meta
    - name: description
      content: Base32 エンコード/デコード | 軽量で意味的、開発者フレンドリーな golang エンコーディング&暗号化ライブラリ
  - - meta
    - name: keywords
      content: dongle, base32, base32hex
---

# Base32

Base32 はバイナリデータを `ASCII` 文字にエンコードする方式で、`32` 個の文字（A-Z, 2-7）を使用してデータを表現します。`dongle` は標準およびストリーミング `Base32` と `Base32Hex` の2つのバリエーションをサポートしています。

- [Base32Std](#base32std)
- [Base32Hex](#base32hex)

## Base32Std
> デフォルト文字セットは `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`、
> `base32.StdAlphabet` を設定して文字セットをカスタマイズできます

### データをエンコード
入力データ

```go
// 文字列を入力
encoder := dongle.Encode.FromString("hello world").ByBase32()
// バイト配列を入力
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase32()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase32()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
encoder.ToString() // NBSWY3DPEB3W64TMMQ======
// バイト配列を出力
encoder.ToBytes()  // []byte("NBSWY3DPEB3W64TMMQ======")
```

### データをデコード
入力データ

```go
// 文字列を入力
decoder := dongle.Decode.FromString("NBSWY3DPEB3W64TMMQ======").ByBase32()
// バイト配列を入力
decoder := dongle.Decode.FromBytes([]byte("NBSWY3DPEB3W64TMMQ======")).ByBase32()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase32()

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

## Base32Hex

> デフォルト文字セットは `0123456789ABCDEFGHIJKLMNOPQRSTUV`、
> `base32.HexAlphabet` を設定して文字セットをカスタマイズできます

### データをエンコード
入力データ

```go
// 文字列を入力
encoder := dongle.Encode.FromString("hello world").ByBase32Hex()
// バイト配列を入力
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase32Hex()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase32Hex()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
encoder.ToString() // D1IMOR3F41RMUSJCCG======
// バイト配列を出力
encoder.ToBytes()  // []byte("D1IMOR3F41RMUSJCCG======")
```

### データをデコード
入力データ

```go
// 文字列を入力
decoder := dongle.Decode.FromString("D1IMOR3F41RMUSJCCG======").ByBase32Hex()
// バイト配列を入力
decoder := dongle.Decode.FromBytes([]byte("D1IMOR3F41RMUSJCCG======")).ByBase32Hex()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase32Hex()

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


