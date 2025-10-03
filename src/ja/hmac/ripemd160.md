---
title: HMAC-RIPEMD160アルゴリズム
head:
  - - meta
    - name: description
      content: HMAC-RIPEMD160アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: HMAC-RIPEMD160
---

# Hmac-Ripemd160

`Hmac-Ripemd160` は `ripemd160` ベースのメッセージ認証コードアルゴリズムです。`dongle` は標準およびストリーミング `ripemd160` メッセージ認証コードアルゴリズムをサポートし、複数の出力形式を提供します。

> 注意：`WithKey` メソッドは `ByRipemd160` の前に呼び出す必要があります

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByRipemd160()

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByRipemd160()

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByRipemd160()

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 3691ad040e80c43dc6e8ffe9bc6ef3d5bd8786b8

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("3691ad040e80c43dc6e8ffe9bc6ef3d5bd8786b8")

// Base64エンコード文字列を出力
hasher.ToBase64String() // NpGtBA6AxD3G6P/pvG7z1b2Hhrg=

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("NpGtBA6AxD3G6P/pvG7z1b2Hhrg=")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```
