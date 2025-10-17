---
title: Blake2b ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: BLAKE2b ハッシュアルゴリズム|軽量で、セマンティック、開発者フレンドリーな golang エンコーディング&暗号ライブラリ
  - - meta
    - name: keywords
      content: ハッシュ, hash, blake2b, blake2b-256, blake2b-384, blake2b-512, hash-blake2b, hash-blake2b-256, hash-blake2b-384, hash-blake2b-512
---

# Hash-Blake2b

`Hash-Blake2b` は異なる長さのハッシュ値を生成するハッシュアルゴリズムのシリーズで、`blake2b-256`、`blake2b-384`、`blake2b-512` を含みます。`dongle` は3つの `hash-blake2b` バリアントすべておよびストリーミングをサポートしています。

- [Blake2b-256](#blake2b-256)：32バイトのハッシュ値を生成
- [Blake2b-384](#blake2b-384)：48バイトのハッシュ値を生成
- [Blake2b-512](#blake2b-512)：64バイトのハッシュ値を生成

## Blake2b-256

### 入力データ

```go
// 文字列入力
hasher := dongle.Hash.FromString("hello world").ByBlake2b(256)
// バイトスライス入力
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2b(256)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2b(256)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610")

// Base64エンコード文字列を出力
hasher.ToBase64String() // JWyDspcRTSAbMBefPw7wys6Xg2ItpZdDJrQ2F4ru9hA=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("JWyDspcRTSAbMBefPw7wys6Xg2ItpZdDJrQ2F4ru9hA=")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```

## Blake2b-384

### 入力データ

```go
// 文字列入力
hasher := dongle.Hash.FromString("hello world").ByBlake2b(384)
// バイトスライス入力
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2b(384)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2b(384)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 8c653f8c9c9aa2177fb6f8cf5bb914828faa032d7b486c8150663d3f6524b086784f8e62693171ac51fc80b7d2cbb12b
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("8c653f8c9c9aa2177fb6f8cf5bb914828faa032d7b486c8150663d3f6524b086784f8e62693171ac51fc80b7d2cbb12b")

// Base64エンコード文字列を出力
hasher.ToBase64String() // jGU/jJyaohd/tvjPW7kUgo+qAy17SGyBUGY9P2UksIZ4T45iaTFxrFH8gLfSy7Er
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("jGU/jJyaohd/tvjPW7kUgo+qAy17SGyBUGY9P2UksIZ4T45iaTFxrFH8gLfSy7Er")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```

## Blake2b-512

### 入力データ

```go
// 文字列入力
hasher := dongle.Hash.FromString("hello world").ByBlake2b(512)
// バイトスライス入力
hasher := dongle.Hash.FromBytes([]byte("hello world")).ByBlake2b(512)
// ファイルストリーム入力
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).ByBlake2b(512)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0")

// Base64エンコード文字列を出力
hasher.ToBase64String() // Ahzth5kpbOylV4MquUGlC0oR+DR4zxQfUfkz9lOrn7zAWgN83b7QbjCb8zSULE5YzfGkbiN5EczX/Pl4fLx/0A==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("Ahzth5kpbOylV4MquUGlC0oR+DR4zxQfUfkz9lOrn7zAWgN83b7QbjCb8zSULE5YzfGkbiN5EczX/Pl4fLx/0A==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```