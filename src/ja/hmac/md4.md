---
title: HMAC-MD4アルゴリズム
head:
  - - meta
    - name: description
      content: HMAC-MD4 メッセージ認証コードアルゴリズム、MD4 ハッシュアルゴリズムに基づき、キーを使用してメッセージ認証を行う、16 バイト認証コードを生成、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, HMAC, メッセージ認証コード, MD4, キー, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hmac-Md4

`Hmac-Md4` は `md4` ベースのメッセージ認証コードアルゴリズムです。`dongle` は標準およびストリーミング `md4` メッセージ認証コードアルゴリズムをサポートし、複数の出力形式を提供します。

> 注意：`WithKey` メソッドは `ByMd4` の前に呼び出す必要があります

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd4()
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByMd4()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByMd4()

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 7a9df5247cbf76a8bc17c9c4f5a75b6b
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("7a9df5247cbf76a8bc17c9c4f5a75b6b")

// Base64エンコード文字列を出力
hasher.ToBase64String() // ep31JHy/dqi8F8nE9adbaw==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("ep31JHy/dqi8F8nE9adbaw==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```
