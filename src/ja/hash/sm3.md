---
title: SM3ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: SM3 ハッシュアルゴリズム、中国国家暗号管理局が発行した国家暗号ハッシュアルゴリズム、32 バイトハッシュ値を生成、GB/T 32918.1-2016 標準に準拠、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, ハッシュ, ダイジェスト, チェックサム, SM3, 国家暗号アルゴリズム, GB/T 32918.1-2016, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hash-Sm3

`Hash-SM3` は `32` バイトのハッシュ値を生成する国家暗号ハッシュアルゴリズムで、中国国家暗号管理局が発行した暗号ハッシュアルゴリズムで、`GB/T 32918.1-2016` 標準に準拠しています。`dongle` は標準およびストリーミング `SM3` ハッシュアルゴリズムをサポートし、複数の出力形式を提供します。

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySm3()
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySm3()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySm3()

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88")

// Base64エンコード文字列を出力
hasher.ToBase64String() // RPAWHmn6b9/CkMSGVUoF3AwFPafly7hO+Trp1tP/+Ig=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("RPAWHmn6b9/CkMSGVUoF3AwFPafly7hO+Trp1tP/+Ig=")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```
