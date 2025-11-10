---
title: MD2ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: MD2 ハッシュアルゴリズム、生成 16 バイトハッシュ値、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, ハッシュ, ダイジェスト, チェック, MD2, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hash-Md2

`Hash-Md2` は `16` バイトのハッシュ値を生成するハッシュアルゴリズムです。`dongle` は標準およびストリーミング `md2` ハッシュアルゴリズムをサポートし、複数の出力形式を提供します。

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").ByMd2()
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByMd2()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByMd2()

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // d9cce882ee690a5c1ce70beff3a78c77
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("d9cce882ee690a5c1ce70beff3a78c77")

// Base64エンコード文字列を出力
hasher.ToBase64String() // 2czogu5pClwc5wvv86eMdw==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("2czogu5pClwc5wvv86eMdw==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```