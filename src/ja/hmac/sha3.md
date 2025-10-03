---
title: HMAC-SHA3アルゴリズム
head:
  - - meta
    - name: description
      content: HMAC-SHA3アルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: HMAC-SHA3
---

# Hmac-Sha3

`Hmac-Sha3` は `sha3` ベースのメッセージ認証コードアルゴリズムです。`dongle` は標準およびストリーミング `sha3` メッセージ認証コードアルゴリズムをサポートし、複数の出力形式を提供します。

> 注意：`WithKey` メソッドは `BySha3` の前に呼び出す必要があります

## サポートされるハッシュアルゴリズム

- [Sha3-224](#sha3-224)：28バイトのハッシュ値を生成
- [Sha3-256](#sha3-256)：32バイトのハッシュ値を生成
- [Sha3-384](#sha3-384)：48バイトのハッシュ値を生成
- [Sha3-512](#sha3-512)：64バイトのハッシュ値を生成

## Sha3-224

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(224)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(224)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(224)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // fb8f061d9d1dddd2f5d3b9064a5e98e3e4b6df27ea93ce67627583ce
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("fb8f061d9d1dddd2f5d3b9064a5e98e3e4b6df27ea93ce67627583ce")

// Base64エンコード文字列を出力
hasher.ToBase64String() // +48GHZ0d3dL107kGSl6Y4+S23yfqk85nYnWDzg==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("+48GHZ0d3dL107kGSl6Y4+S23yfqk85nYnWDzg==")

// エンコードなしの生文字列を出力
hasher.ToRawString()
// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```

## Sha3-256

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(256)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(256)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(256)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 8193367fde28cf5c460adb449a04b3dd9c184f488bdccbabf0526c54f90c4460
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("8193367fde28cf5c460adb449a04b3dd9c184f488bdccbabf0526c54f90c4460")

// Base64エンコード文字列を出力
hasher.ToBase64String() // gZM2f94oz1xGCttEmgSz3ZwYT0iL3Mur8FJsVPkMRGA=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("gZM2f94oz1xGCttEmgSz3ZwYT0iL3Mur8FJsVPkMRGA=")

// エンコードなしの生文字列を出力
hasher.ToRawString()
// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```

## Sha3-384

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(384)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(384)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(384)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 3f76f5cda69cada3ee6b33f8458cd498b063075db263dd8b33f2a3992a8804f9569a7c86ffa2b8f0748babeb7a6fc0e7
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("3f76f5cda69cada3ee6b33f8458cd498b063075db263dd8b33f2a3992a8804f9569a7c86ffa2b8f0748babeb7a6fc0e7")

// Base64エンコード文字列を出力
hasher.ToBase64String() // P3b1zaacraPuazP4RYzUmLBjB12yY92LM/KjmSqIBPlWmnyG/6K48HSLq+t6b8Dn
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("P3b1zaacraPuazP4RYzUmLBjB12yY92LM/KjmSqIBPlWmnyG/6K48HSLq+t6b8Dn")

// エンコードなしの生文字列を出力
hasher.ToRawString()
// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```

## Sha3-512

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).BySha3(512)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).BySha3(512)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).BySha3(512)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // a99653d0407d659eccdeed43bb7cccd2e2b05a2c34fd3467c4198cf2ad26a466738513e88839fb55e64eb49df65bc52ed0fec2775bd9e086edd4fb4024add4a2
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("a99653d0407d659eccdeed43bb7cccd2e2b05a2c34fd3467c4198cf2ad26a466738513e88839fb55e64eb49df65bc52ed0fec2775bd9e086edd4fb4024add4a2")

// Base64エンコード文字列を出力
hasher.ToBase64String() // qZZT0EB9ZZ7M3u1Du3zM0uKwWiw0/TRnxBmM8q0mpGZzhRPoiDn7VeZOtJ32W8Uu0P7Cd1vZ4Ibt1PtAJK3Uog==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("qZZT0EB9ZZ7M3u1Du3zM0uKwWiw0/TRnxBmM8q0mpGZzhRPoiDn7VeZOtJ32W8Uu0P7Cd1vZ4Ibt1PtAJK3Uog==")

// エンコードなしの生文字列を出力
hasher.ToRawString()
// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```
