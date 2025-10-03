---
title: SHA3ハッシュアルゴリズム
head:
  - - meta
    - name: description
      content: SHA3ハッシュアルゴリズム | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
  - - meta
    - name: keywords
      content: ハッシュ, hash, sha3, sha224, sha256, sha384, sha512
---

# Hash-Sha3

`Hash-Sha3` は異なる長さのハッシュ値を生成する一連のハッシュアルゴリズムで、`sha3-224`、`sha3-256`、`sha3-384`、`sha3-512` を含みます。`dongle` はすべての4つの `hash-sha3` バリアントおよびストリーミングをサポートしています。

- [Sha3-224](#sha3-224)：28バイトのハッシュ値を生成
- [Sha3-256](#sha3-256)：32バイトのハッシュ値を生成
- [Sha3-384](#sha3-384)：48バイトのハッシュ値を生成
- [Sha3-512](#sha3-512)：64バイトのハッシュ値を生成

## Sha3-224

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySha3(224)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(224)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(224)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5")

// Base64エンコード文字列を出力
hasher.ToBase64String() // 37fxjHfpKLtW+ustonKRvXkLwQRc3kXzIQu2xQ==

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("37fxjHfpKLtW+ustonKRvXkLwQRc3kXzIQu2xQ==")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```

## Sha3-256

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySha3(256)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(256)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(256)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938")

// Base64エンコード文字列を出力
hasher.ToBase64String() // ZEvMflZDcwQJmarInnYi88px+6HZcv2Uoxw7+/JOOTg=

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("ZEvMflZDcwQJmarInnYi88px+6HZcv2Uoxw7+/JOOTg=")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```

## Sha3-384

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySha3(384)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(384)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(384)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b")

// Base64エンコード文字列を出力
hasher.ToBase64String() // g7/yjd4bG/WBAHHGZDwI5bBb24Nu/9cLQD6o6gpjTcSZfrEFOqNZP1kPnGNjDdkL

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("g7/yjd4bG/WBAHHGZDwI5bBb24Nu/9cLQD6o6gpjTcSZfrEFOqNZP1kPnGNjDdkL")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```

## Sha3-512

### 入力データ

```go
// 入力文字列
hasher := dongle.Hash.FromString("hello world").BySha3(512)

// 入力バイトスライス
hasher := dongle.Hash.FromBytes([]byte("hello world")).BySha3(512)

// 入力ファイルストリーム
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).BySha3(512)

// ハッシュエラーをチェック
if hasher.Error != nil {
	fmt.Printf("ハッシュエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a

// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a")

// Base64エンコード文字列を出力
hasher.ToBase64String() // hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0/4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg==

// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("hAAGZT6ayelRF6FckVyquBZikY6SXengBPd0/4LXB5pA1NJ7GzcmV8YdRtRwMEyIx4izpFJ60HTR3MvuXbqpmg==")

// エンコードなしの生文字列を出力
hasher.ToRawString()

// エンコードなしの生バイトスライスを出力
hasher.ToRawBytes()
```