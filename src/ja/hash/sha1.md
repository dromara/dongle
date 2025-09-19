---
title: SHA1ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: SHA1ハッシュアルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: ハッシュ, hash, sha1
---

# Hash-Sha1

`Hash-Sha1` は `20` バイトのハッシュ値を生成するハッシュアルゴリズムです。`dongle` は標準的な `sha1` ハッシュアルゴリズムをサポートし、複数の出力形式を提供します。

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

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```
