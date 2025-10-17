---
title: HMAC-BLAKE2sアルゴリズム
head:
  - - meta
    - name: description
      content: HMAC-BLAKE2sアルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: メッセージ認証コード, hmac, blake2s, blake2s-128, blake2s-256, hmac-blake2s, hmac-blake2s-128, hmac-blake2s-256
---

# Hmac-Blake2s

`Hmac-Blake2s` は `blake2s` ベースのメッセージ認証コードアルゴリズムです。`dongle` は標準およびストリーミング `blake2s` メッセージ認証コードアルゴリズムをサポートし、複数の出力形式を提供します。

> 注意：`WithKey` メソッドは `ByBlake2s` の前に呼び出す必要があります

## サポートされているハッシュアルゴリズム

- [Blake2s-128](#blake2s-128): 16バイトのハッシュ値を生成
- [Blake2s-256](#blake2s-256): 32バイトのハッシュ値を生成

## Blake2s-128

### 入力データ

```go
// 文字列入力
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2s(128)
// バイトスライス入力
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2s(128)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2s(128)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 8e9dce350baec849c2bc163d0e73552a
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("8e9dce350baec849c2bc163d0e73552a")

// Base64エンコード文字列を出力
hasher.ToBase64String() // jp3ONQuuyEnCvBY9DnNVKg==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("jp3ONQuuyEnCvBY9DnNVKg==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```

## Blake2s-256

### 入力データ

```go
// 文字列入力
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2s(256)
// バイトスライス入力
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2s(256)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2s(256)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 14953619e2781ed4a20f571d32d494af37b92e9bede33fbe429dff376f233af3
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("14953619e2781ed4a20f571d32d494af37b92e9bede33fbe429dff376f233af3")

// Base64エンコード文字列を出力
hasher.ToBase64String() // FJU2GeJ4HtSiD1cdMtSUrze5Lpvt4z++Qp3/N28jOvM=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("FJU2GeJ4HtSiD1cdMtSUrze5Lpvt4z++Qp3/N28jOvM=")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```