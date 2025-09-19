---
title: MD4ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: MD4ハッシュアルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: ハッシュ, hash, md4
---

# Hash-Md4

`Hash-Md4` は `16` バイトのハッシュ値を生成するハッシュアルゴリズムです。`dongle` は標準的な `md4` ハッシュアルゴリズムをサポートし、複数の出力形式を提供します。

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

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```