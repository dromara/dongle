---
title: Blake2s ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: Blake2s ハッシュアルゴリズム、blake2s-128（キーが必要）と blake2s-256 の2つのバリアントを提供、標準およびストリーミング処理をサポート、文字列、バイト、ファイル入力をサポート、Hex および Base64 出力形式をサポート
  - - meta
    - name: keywords
      content: dongle, go-dongle, ハッシュ, ダイジェスト, チェックサム, Blake2s, blake2s-128, blake2s-256, キー, ストリーミング処理, 文字列入力, バイト入力, ファイル入力, Hex, Base64
---

# Hash-Blake2s

`Hash-Blake2s` は異なる長さのハッシュ値を生成するハッシュアルゴリズムのシリーズで、`blake2s-128` と `blake2s-256` を含みます。`dongle` は2つの `hash-blake2s` バリアントすべておよびストリーミングをサポートしています。

- [Blake2s-128](#blake2s-128)：16バイトのハッシュ値を生成
- [Blake2s-256](#blake2s-256)：32バイトのハッシュ値を生成

## Blake2s-128

### 入力データ

```go
// 文字列入力（キーが必要）
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("secret")).ByBlake2s(128)
// バイトスライス入力（キーが必要）
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("secret")).ByBlake2s(128)
// ファイルストリーム入力（キーが必要）
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("secret")).ByBlake2s(128)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 8f9dff49538583cb967e763c54d51280
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("8f9dff49538583cb967e763c54d51280")

// Base64エンコード文字列を出力
hasher.ToBase64String() // j53/SVOFg8uWfnY8VNUSgA==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("j53/SVOFg8uWfnY8VNUSgA==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```

## Blake2s-256

### 入力データ

```go
// 文字列入力
hasher := dongle.Hash.FromString("hello world").ByBlake2s(256)
// バイトスライス入力
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2s(256)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2s(256)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b")

// Base64エンコード文字列を出力
hasher.ToBase64String() // muxoBnlFYRB+WUsfaoprDJKgy6ms9eXpPMoG94GBOws=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("muxoBnlFYRB+WUsfaoprDJKgy6ms9eXpPMoG94GBOws=")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```