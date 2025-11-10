---
title: SHA1ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: SHA1 ハッシュアルゴリズム、生成 20 バイトハッシュ値、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, ハッシュ, ダイジェスト, チェック, SHA1, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hash-Sha1

`Hash-Sha1` は `20` バイトのハッシュ値を生成するハッシュアルゴリズムです。`dongle` は標準およびストリーミング `sha1` ハッシュアルゴリズムをサポートし、複数の出力形式を提供します。

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySha1()
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha1()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha1()

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")

// Base64エンコード文字列を出力
hasher.ToBase64String() // Kq5sNclPz7QV2+lfQIuc6R7oRu0=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("Kq5sNclPz7QV2+lfQIuc6R7oRu0=")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```
