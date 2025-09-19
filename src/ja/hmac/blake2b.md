---
head:
  - - meta
    - name: description
      content: HMAC-BLAKE2bアルゴリズム|軽量で、セマンティック、開発者フレンドリーな golang エンコーディング&暗号ライブラリ
  - - meta
    - name: keywords
      content: HMAC-BLAKE2b
---

# Hmac-Blake2b

`Hmac-Blake2b` は `blake2b` ベースのメッセージ認証コードアルゴリズムです。`dongle` は標準の `blake2b` メッセージ認証コードアルゴリズムをサポートし、複数の出力形式を提供します。

> 注意：`WithKey` メソッドは `ByBlake2b` の前に呼び出す必要があります

## サポートされているハッシュアルゴリズム

- [Blake2b-256](#blake2b-256)：32バイトのハッシュ値を生成
- [Blake2b-384](#blake2b-384)：48バイトのハッシュ値を生成
- [Blake2b-512](#blake2b-512)：64バイトのハッシュ値を生成

## Blake2b-256

### 入力データ

```go
// 文字列入力
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2b(256)

// バイトスライス入力
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2b(256)

// ファイルストリーム入力
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2b(256)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 11de19238a5d5414bc8f9effb2a5f004a4210804668d25d252d0733c26670a0d
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("11de19238a5d5414bc8f9effb2a5f004a4210804668d25d252d0733c26670a0d")

// Base64エンコード文字列を出力
hasher.ToBase64String() // Ed4ZI4pdVBS8j57/sqXwBKQhCARmjSXSUtBzPCZnCg0=
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("Ed4ZI4pdVBS8j57/sqXwBKQhCARmjSXSUtBzPCZnCg0=")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```

## Blake2b-384

### 入力データ

```go
// 文字列入力
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2b(384)

// バイトスライス入力
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2b(384)

// ファイルストリーム入力
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2b(384)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 506c397b0b5d437342a07748d09612f9905ab21e6674d8409516a53cf341a1bc9052bf47edf85ffe506437acd1f91bc
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("506c397b0b5d437342a07748d09612f9905ab21e6674d8409516a53cf341a1bc9052bf47edf85ffe506437acd1f91bc")

// Base64エンコード文字列を出力
hasher.ToBase64String() // UGw5ewtdQ3NCoHdI0JYS+ZBash5mdNhAlRalPPNBobyQUr9H7fhf/lBkOnrNH5G8
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("UGw5ewtdQ3NCoHdI0JYS+ZBash5mdNhAlRalPPNBobyQUr9H7fhf/lBkOnrNH5G8")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```

## Blake2b-512

### 入力データ

```go
// 文字列入力
hasher := dongle.Hash.FromString("hello world").WithKey([]byte("dongle")).ByBlake2b(512)

// バイトスライス入力
hasher := dongle.Hash.FromBytes([]byte("hello world")).WithKey([]byte("dongle")).ByBlake2b(512)

// ファイルストリーム入力
file, _ := os.Open("test.txt")
hasher := dongle.Hash.FromFile(file).WithKey([]byte("dongle")).ByBlake2b(512)

// HMACエラーをチェック
if hasher.Error != nil {
	fmt.Printf("HMACエラー: %v\n", hasher.Error)
	return
}
```

### 出力データ

```go
// Hexエンコード文字列を出力
hasher.ToHexString() // 9ab7280ca18d0fca29034329eddecb36ecdcefe00758bbe966e30cfbf9774e3e21c2ee5be01fdc23c983d8849fcf2f0dcfd3a0e6ba92442cbd64a2342763d2ae
// Hexエンコードバイトスライスを出力
hasher.ToHexBytes()  // []byte("9ab7280ca18d0fca29034329eddecb36ecdcefe00758bbe966e30cfbf9774e3e21c2ee5be01fdc23c983d8849fcf2f0dcfd3a0e6ba92442cbd64a2342763d2ae")

// Base64エンコード文字列を出力
hasher.ToBase64String() // mrcoDKGND8opA0Mp7d7LNuzc7+AHWLvpZuMM+/l3Tj4hwu5b4B/cI8mD2ISfzy8Nz9Og5rqSRCy9ZKI0J2PSrg==
// Base64エンコードバイトスライスを出力
hasher.ToBase64Bytes()  // []byte("mrcoDKGND8opA0Mp7d7LNuzc7+AHWLvpZuMM+/l3Tj4hwu5b4B/cI8mD2ISfzy8Nz9Og5rqSRCy9ZKI0J2PSrg==")

// エンコードされていない生の文字列を出力
hasher.ToRawString()
// エンコードされていない生のバイトスライスを出力
hasher.ToRawBytes()
```