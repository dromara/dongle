---
title: HMAC-SM3アルゴリズム
head:
  - - meta
    - name: description
      content: HMAC-SM3アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: HMAC-SM3
---

# Hmac-Sm3

`Hmac-Sm3` は `sm3` ベースのメッセージ認証コードアルゴリズムです。`dongle` は標準およびストリーミング `sm3` メッセージ認証コードアルゴリズムをサポートし、複数の出力形式を提供します。

> 注意：`WithKey` メソッドは `BySm3` の前に呼び出す必要があります

## 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySm3()

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySm3()

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySm3()

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

## 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 8c733aae1d553c466a08c3e9e5daac3e99ae220181c7c1bc8c2564961de751b3

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("8c733aae1d553c466a08c3e9e5daac3e99ae220181c7c1bc8c2564961de751b3")

// Base64エンコード文字列を出力
hasher.ToBase64String() // jHM6rh1VPEZqCMPp5dqsPpmuIgGBx8G8jCVklh3nUbM=

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("jHM6rh1VPEZqCMPp5dqsPpmuIgGBx8G8jCVklh3nUbM=")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```
