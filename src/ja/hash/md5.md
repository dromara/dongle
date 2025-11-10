---
title: MD5ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: MD5 ハッシュアルゴリズム、16 バイトハッシュ値を生成、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, ハッシュ, ダイジェスト, チェックサム, MD5, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hash-Md5

`Hash-Md5` は `16` バイトのハッシュ値を生成するハッシュアルゴリズムです。`dongle` は標準およびストリーミング `md5` ハッシュアルゴリズムをサポートし、複数の出力形式を提供します。

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").ByMd5()
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByMd5()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByMd5()

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 5eb63bbbe01eeed093cb22bb8f5acdc3
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("5eb63bbbe01eeed093cb22bb8f5acdc3")

// Base64エンコード文字列を出力
hasher.ToBase64String() // XrY7u+Ae7tCTyyK7j1rNww==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("XrY7u+Ae7tCTyyK7j1rNww==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
``` 