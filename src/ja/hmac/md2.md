---
title: HMAC-MD2アルゴリズム
head:
  - - meta
    - name: description
      content: HMAC-MD2アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: メッセージ認証コード, hmac, md2, hmac-md2
---

# Hmac-Md2

`Hmac-Md2` は `md2` ベースのメッセージ認証コードアルゴリズムです。`dongle` は標準およびストリーミング `md2` メッセージ認証コードアルゴリズムをサポートし、複数の出力形式を提供します。

> 注意：`WithKey` メソッドは `ByMd2` の前に呼び出す必要があります

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByMd2()
// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByMd2()
// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByMd2()

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 88ed6ef9ab699d03a702f2a6fb1c0673
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("88ed6ef9ab699d03a702f2a6fb1c0673")

// Base64エンコード文字列を出力
hasher.ToBase64String() // iO1u+atpnQOnAvKm+xwGcw==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("iO1u+atpnQOnAvKm+xwGcw==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```
