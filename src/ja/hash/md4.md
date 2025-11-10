---
title: MD4ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: MD4 ハッシュアルゴリズム、生成 16 バイトハッシュ値、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, ハッシュ, ダイジェスト, チェック, MD4, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hash-Md4

`Hash-Md4` は `16` バイトのハッシュ値を生成するハッシュアルゴリズムです。`dongle` は標準およびストリーミング `md4` ハッシュアルゴリズムをサポートし、複数の出力形式を提供します。

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").ByMd4()
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByMd4()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByMd4()

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // aa010fbc1d14c795d86ef98c95479d17
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("aa010fbc1d14c795d86ef98c95479d17")

// Base64エンコード文字列を出力
hasher.ToBase64String() // qgEPvB0Ux5XYbvmMlUedFw==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("qgEPvB0Ux5XYbvmMlUedFw==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```