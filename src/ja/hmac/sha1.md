---
title: HMAC-SHA1アルゴリズム
head:
  - - meta
    - name: description
      content: HMAC-SHA1 メッセージ認証コードアルゴリズム、SHA1 ハッシュアルゴリズムに基づき、キーを使用してメッセージ認証を行う、20 バイト認証コードを生成、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, HMAC, メッセージ認証コード, SHA1, キー, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hmac-Sha1

`Hmac-Sha1` は `sha1` ベースのメッセージ認証コードアルゴリズムです。`dongle` は標準およびストリーミング `sha1` メッセージ認証コードアルゴリズムをサポートし、複数の出力形式を提供します。

> 注意：`WithKey` メソッドは `BySha1` の前に呼び出す必要があります

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha1()
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha1()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha1()

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 91c103ef93ba7420902b0d1bf0903251c94b4a62
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("91c103ef93ba7420902b0d1bf0903251c94b4a62")

// Base64エンコード文字列を出力
hasher.ToBase64String() // kcED75O6dCCQKw0b8JAyUclLSmI=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("kcED75O6dCCQKw0b8JAyUclLSmI=")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```
