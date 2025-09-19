---
title: MD2ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: MD2ハッシュアルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: ハッシュ, hash, md2
---

# Hash-Md2

`Hash-Md2` は `16` バイトのハッシュ値を生成するハッシュアルゴリズムです。`dongle` は標準的な `md2` ハッシュアルゴリズムをサポートし、複数の出力形式を提供します。

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

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```