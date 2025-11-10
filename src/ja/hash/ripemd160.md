---
title: RIPEMD160ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: RIPEMD160 ハッシュアルゴリズム、生成 20 バイトハッシュ値、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, ハッシュ, ダイジェスト, チェック, RIPEMD160, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hash-Ripemd160

`Hash-Ripemd160` は `20` バイトのハッシュ値を生成するハッシュアルゴリズムです。`dongle` は標準およびストリーミング `ripemd160` ハッシュアルゴリズムをサポートし、複数の出力形式を提供します。

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").ByRipemd160()
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByRipemd160()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByRipemd160()

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f")

// Base64エンコード文字列を出力
hasher.ToBase64String() // mMYVeEzLX+WTb7wMvp39tAjZLw8=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("mMYVeEzLX+WTb7wMvp39tAjZLw8=")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```
