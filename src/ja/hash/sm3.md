---
title: SM3ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: SM3ハッシュアルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: ハッシュ, hash, sm3
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

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```
