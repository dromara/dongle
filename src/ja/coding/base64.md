---
title: Base64 エンコード/デコード
head:
  - - meta
    - name: description
      content: Base64 エンコード/デコード | 軽量で意味的、開発者フレンドリーな golang エンコーディング&暗号化ライブラリ
  - - meta
    - name: keywords
      content: dongle, base64, base64url
---

# Base64

Base64 はバイナリデータを `ASCII` 文字にエンコードする方式で、`64` 個の文字（A-Z, a-z, 0-9, +, /）を使用してデータを表現します。`dongle` は標準およびストリーミング `Base64` と `Base64Url` の2つのバリエーションをサポートしています。

- [Base64Std](#base64std)
- [Base64Url](#base64url)

## Base64Std
> デフォルト文字セットは `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`、
> `base64.StdAlphabet` を設定して文字セットをカスタマイズできます

### データをエンコード
入力データ

```go
// 文字列を入力
encoder := dongle.Encode.FromString("hello world").ByBase64()
// バイト配列を入力
encoder := dongle.Encode.FromBytes([]byte("hello world")).ByBase64()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase64()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
encoder.ToString() // aGVsbG8gd29ybGQ=
// バイト配列を出力
encoder.ToBytes()  // []byte("aGVsbG8gd29ybGQ=")
```

### データをデコード
入力データ

```go
// 文字列を入力
decoder := dongle.Decode.FromString("aGVsbG8gd29ybGQ=").ByBase64()
// バイト配列を入力
decoder := dongle.Decode.FromBytes([]byte("aGVsbG8gd29ybGQ=")).ByBase64()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase64()

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

## Base64Url

> デフォルト文字セットは `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_`、
> `base64.URLAlphabet` を設定して文字セットをカスタマイズできます

### データをエンコード
入力データ

```go
// 文字列を入力
encoder := dongle.Encode.FromString("https://dongle.go-pkg.com/api/v1/data+test").ByBase64Url()
// バイト配列を入力
encoder := dongle.Encode.FromBytes([]byte("https://dongle.go-pkg.com/api/v1/data+test")).ByBase64Url()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
encoder := dongle.Encode.FromFile(file).ByBase64Url()

// エンコードエラーをチェック
if encoder.Error != nil {
	fmt.Printf("エンコードエラー: %v\n", encoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
encoder.ToString() // aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0
// バイト配列を出力
encoder.ToBytes()  // []byte("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0")
```

### データをデコード
入力データ

```go
// 文字列を入力
decoder := dongle.Decode.FromString("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0").ByBase64Url()
// バイト配列を入力
decoder := dongle.Decode.FromBytes([]byte("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0")).ByBase64Url()
// ファイルストリームを入力
file, _ := os.Open("test.txt")
decoder := dongle.Decode.FromFile(file).ByBase64Url()

// デコードエラーをチェック
if decoder.Error != nil {
	fmt.Printf("デコードエラー: %v\n", decoder.Error)
	return
}
```

出力データ

```go
// 文字列を出力
decoder.ToString() // https://dongle.go-pkg.com/api/v1/data+test
// バイト配列を出力
decoder.ToBytes()  // []byte("https://dongle.go-pkg.com/api/v1/data+test")
```


