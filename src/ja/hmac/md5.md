---
title: HMAC-MD5アルゴリズム
head:
  - - meta
    - name: description
      content: HMAC-MD5アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: HMAC-MD5
---

# Hmac-Md5

`Hmac-Md5` は `md5` ベースのメッセージ認証コードアルゴリズムです。`dongle` は標準的な `md5` メッセージ認証コードアルゴリズムをサポートし、複数の出力形式を提供します。

> 注意：`WithKey` メソッドは `ByMd5` の前に呼び出す必要があります

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd5()

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByMd5()

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByMd5()

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 4790626a275f776956386e5a3ea7b726

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("4790626a275f776956386e5a3ea7b726")

// Base64エンコード文字列を出力
hasher.ToBase64String() // R5Biaidfd2lWOG5aPqe3Jg==

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("R5Biaidfd2lWOG5aPqe3Jg==")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```
