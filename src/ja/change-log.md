---
head:
  - - meta
    - name: description
      content: 更新ログ | 軽量で、セマンティックで、開発者フレンドリーなgolang エンコード&暗号ライブラリ
---

# 更新ログ
## [v1.3.0](https://github.com/dromara/dongle/compare/v1.2.3...v1.3.0) (2026-10-19)

### ✨ 新機能

- **`Sm2` に `ASN.1` 形式の暗号文と署名形式を追加**：`Sm2CipherMode` に `ASN1C1C2C3` と `ASN1C1C3C2` を追加し、暗号文を DER の `SEQUENCE { x INTEGER, y INTEGER, C2 OCTET STRING, C3 OCTET STRING }` として扱えるようになりました。BouncyCastle、Java、多くの国密ゲートウェイが出力する形式で、従来の `C1 || C2 || C3`、`C1 || C3 || C2` という生バイトの並びに限定されません。あわせて `Sm2SingMode`（既定は `ASN1`、`Bytes` も選択可）と `SetSingMode` を追加し、署名は DER の `SEQUENCE { r, s }` または固定 64 バイトの `r || s` になります。どちらも `cryptobyte` で解析するため、切り詰められたデータや DER でないデータは黙って誤読されずエラーを返します。`NewSm2KeyPair` の既定値は `ASN1` のままです（by [@Web-Coke](https://github.com/Web-Coke) in [#40](https://github.com/dromara/dongle/pull/40)）
- **モールス符号表を ITU-R M.1677-1 の全表と国際拡張文字に拡張**：`¡`、`¿`、`å`/`Å`、`ä`/`Ä`、`é`/`É`、`ñ`/`Ñ`、`ó`/`Ó`、`ö`/`Ö`、`ú`/`Ú` を追加し、符号は codigomorse.org に準拠、各グループが対応する ITU 条項も明記しました。`/` は句読点グループに移動しています。**注意**：既存の 2 つのマッピングが変わります。`<` は `.--.-` から `.--.--` へ（`.--.-` は `å` に割り当て）、`\n` は `.-..-..` へ変更され `\r` と符号を共有しなくなります。`v1.2.3` でエンコードしたこれらの文字はデコード結果が変わります（by [@htlsmilework](https://github.com/htlsmilework) in [#42](https://github.com/dromara/dongle/pull/42)）

### 🐛 修正

- **`z` 省略形がある場合に ascii85 デコードの出力が切り詰められるバグを修正**：`encoding/ascii85` は全ゼロの 4 バイトグループを単一の `z` に変換し、本ライブラリのエンコーダーも同様ですが、デコーダーは文字数から 5:4 の比率で出力長を再計算し、標準ライブラリの正しい結果をその長さに切り詰めていました。そのため 5 ゼロバイトが 2 バイトに、8 ゼロバイトが 1 バイトになり、しかもエラーは返りませんでした。現在は `z` をこの比率から除外して 4 バイトとして数え、省略形が含む展開量に応じて出力バッファを確保します（by [@youdie006](https://github.com/youdie006) in [#44](https://github.com/dromara/dongle/pull/44)）
- **ゼログループが 4 つ以上ある場合に ascii85 デコードが失敗するバグを修正**：上記の長さ修正後も `u` のパディングが `len(src)%5` を使っており、`z` 省略形があると最後のグループが 1 文字だけになることがありました。`encoding/ascii85` はこの入力を拒否するため、16 ゼロバイト（`zzzz` とエンコード）はまったくデコードできませんでした。現在は 2 つのデコーダーとも `z` 以外の長さでパディングします（by [@youdie006](https://github.com/youdie006) in [#47](https://github.com/dromara/dongle/pull/47)）
- **base58、base62 のストリーム処理結果がバッチ API と一致しないバグを修正**：どちらの符号化も入力を 1 つの大きな整数として扱うため独立したブロックに分割できませんが、ストリームエンコーダーは 8 バイトずつ、ストリームデコーダーは 1024 バイトずつ処理していました。その結果 `Encode.FromFile(...).ByBase58()`、`ByBase62()` は同じデータの `FromBytes()` と異なる結果を返し、しかもその結果は元に戻せませんでした。現在はドキュメントの記載どおりストリームエンコーダーが入力をバッファリングして `Close` で一度にエンコードし、デコーダーは入力全体を読み込んで一度にデコードし、消費に合わせてバッファを解放します（by [@Shaisolaris](https://github.com/Shaisolaris) in [#48](https://github.com/dromara/dongle/pull/48)）
- **鍵ペアが他ツール生成の鍵を受け付けず、アルゴリズム不一致で panic するバグを修正**：以前は `GenKeyPair` の出力とバイト単位で一致する鍵（`PUBLIC KEY`/`PRIVATE KEY` PEM ブロックに PKIX または PKCS#8 DER を格納したもの）だけを受け付けていました。多くの SM2、Ed25519 生成器が出力する base64 や生の鍵素材は `invalid public key: <nil>` や不可解な ASN.1 エラーで失敗し、RSA の鍵を Ed25519 鍵ペアに渡すと型アサーションの結果を検査していないため panic していました（[#41](https://github.com/dromara/dongle/issues/41)）。現在はすべての `Parse*`、`Format*`、`Set*` メソッドが共通のセレクタを通り、PEM、base64（4 種類のアルファベット、パディングあり/なし）、16 進数、生の鍵素材を順に試し、各アルゴリズムのパーサーが成立する解釈を選びます。Ed25519 は PKIX/PKCS#8 DER、32 バイトのシード、64 バイトの秘密鍵を、SM2 は PKIX/PKCS#8 DER、65 バイトの非圧縮点、32 バイトのスカラーを、RSA は PKIX/PKCS#1 DER を受け付けます。SM2 の鍵フォーマットは `crypto/x509` が SM2 を扱えないためローカルの SPKI/PKCS#8 エンコーダーに置き換え、出力は OpenSSL、Java で引き続き解析できます。`Set*Key` は PEM を受け取って正規化し、アルゴリズムや向きが異なるブロックは解析前に `UnsupportedKeyFormatError`（`the parsed key is an RSA key, not an Ed25519 key`）で拒否します。エラーメッセージから `<nil>` が消え、`Compress*Key` は文字列操作ではなく `pem.Decode` を使うため任意のヘッダーを扱えます。SM2 の秘密鍵スカラーは `[1, n-1]` の範囲を検証するようになりました（以前は `d = 0` で公開点を持たない鍵が生成されました）（by [@gouguolei](https://github.com/gouguolei) in [012269d](https://github.com/dromara/dongle/commit/012269d4b1b58d58d4f1df3b816d276084cc545d)）

### ⚡ パフォーマンス

- **モールスデコードで逆引き表を 1 度だけ構築し、記号ごとの走査を廃止**：`StdDecoder.Decode` は記号ごとに `StdAlphabet` 全体を走査して一致する符号を探していたため、デコードは O(n) ではなく O(n × 89) になり、CPU プロファイルの 53% を map の反復が占めていました。base45、base91 と同じく `init()` で逆引き表を一度だけ構築するようにし、幾何平均で 89.21% 短縮（4096 文字：1222µs → 103µs）、割り当て回数は変わりません。この走査は結果の非決定性も招いていました。7 つの符号が大文字と小文字の組で共有されており（`.--.-` は `Å` と `å`、`ä`、`é`、`ñ`、`ó`、`ö`、`ú` も同様）、map の反復順はランダムなため `.--.-` は 62% の確率で `Å` にデコードされ、これらの文字はエンコード後に元へ戻せませんでした。逆引き表はこの衝突を小文字に統一し、これは `Encode` が生成しうる唯一の形式です（by [@darakanoit](https://github.com/darakanoit) in [#46](https://github.com/dromara/dongle/pull/46)）

### 🔧 リファクタリング

- **鍵のシリアライズをパッケージレベルの関数変数に集約**：`marshalPKIXPublicKey`、`marshalPKCS8PrivateKey` は `crypto/x509` を包む変数になり、`marshalSm2PublicKey`、`marshalSm2PrivateKey` はローカルの SM2 エンコーダーを包みます。これにより `Format*Key` のエラー分岐をテストで再現できます（型付きの鍵に対して `crypto/x509` は決して失敗しないため）。RSA、Ed25519、SM2 のフォーマットはすべてこれらを経由します（by [@gouguolei](https://github.com/gouguolei) in [e314c99](https://github.com/dromara/dongle/commit/e314c992215bc824c8f645e19edc3f29560ddf54) [6ad47b4](https://github.com/dromara/dongle/commit/6ad47b474792c1e13502a5a7fb0df7ab6bf2e920) [0769ea0](https://github.com/dromara/dongle/commit/0769ea0d969de33899ff629a5307e5758e8b2f86) [2c9ad5a](https://github.com/dromara/dongle/commit/2c9ad5a7bc0ff1ea0b2957b910328c33d8c6b98e)）
- **RSA ストリーム検証を簡素化し、未使用のストリームバッファを削除**：`rsa.StreamVerifier.verify` はエラーが nil なら常に true だった `valid` を返さず `error` のみを返します。`unicode.StreamEncoder`、`unicode.StreamDecoder` から未使用の固定 `[512]byte` バッファを削除し、モールスのエラーメッセージはプレースホルダーのない `fmt.Sprintf` ではなく文字列リテラルを使います（by [@gouguolei](https://github.com/gouguolei) in [68dad92](https://github.com/dromara/dongle/commit/68dad927bbb23e6c75558a4777f30e206eb99697)）
- **`SetSingMode` の逆のアサーションを修正し、SM2 の既定値を明示的に初期化**：clamp テストは `SetSingMode(Bytes)` の後も `SingMode` が `ASN1` のままであることを期待していましたが、setter は単に代入するため成立しません。また `NewSm2KeyPair` はゼロ値が偶然 `ASN1` であることに依存していました。現在はコンストラクタが `SingMode: ASN1` を明示的に設定し、テストは両方向を検証します（by [@gouguolei](https://github.com/gouguolei) in [079efab](https://github.com/dromara/dongle/commit/079efab2892b66028898fe430d0649e41bc7302e)）
- **テストの整理と拡充**：24 のテストファイルから未使用の変数と重複ケースを削除し、`key_format_test.go`、`key_test.go` を追加して鍵素材のヘルパー、各種 `UnsupportedKeyFormatError` のメッセージ、公開 API の拒否経路、SM2 の DER と秘密鍵スカラー範囲の分岐をカバーしました。`keypair` のステートメントカバレッジは 97.7% に向上しています（by [@gouguolei](https://github.com/gouguolei) in [372209d](https://github.com/dromara/dongle/commit/372209db32677f5b9e8bab6547354196d501c463) [12c3e11](https://github.com/dromara/dongle/commit/12c3e11bf317e7643f932d8e8505bf2a08c6067b)）

### 🚀 CI

- **golangci-lint のワークフローと設定を追加**：`lint.yml` は master への push と pull request で `v2.15.0` に固定した `golangci-lint-action@v9` を実行し、権限は `contents: read` のみです。`.golangci.yml` は標準セットに `misspell`、`unconvert`、`unparam`、`whitespace` を加え、主観の強い `staticcheck` のスタイル検査（`ST1000`–`ST1022`、`QF1001`）を無効化し、`errcheck` から `(io.Seeker).Seek` を除外します（ストリームの巻き戻しは設計上ベストエフォートのため）。README は Go Report Card のバッジをこのワークフローのステータスバッジに置き換えました（by [@gouguolei](https://github.com/gouguolei) in [1487675](https://github.com/dromara/dongle/commit/1487675d98fba9e5238ca93acb1371be045151a6) [0517244](https://github.com/dromara/dongle/commit/05172446a907de460cc6c867c6c7b9c3ccf89e46)）

### 📝 ドキュメント

- **README の画像をリポジトリから配信し、ドキュメントサイトへの依存を解消**：ロゴ、GVP と G-Star のバナー、JetBrains のロゴは `assets/` を参照するようになり、英語、中国語、日本語の README は `dongle.go-pkg.com` に依存しなくなりました（by [@gouguolei](https://github.com/gouguolei) in [19bffd5](https://github.com/dromara/dongle/commit/19bffd59a533b482779a06257c5c94817724bca8)）

::: details What's Changed (19)

- add ASN.1 support by [@Web-Coke](https://github.com/Web-Coke) in [#40](https://github.com/dromara/dongle/pull/40)
- fix(morse): Add some code from codigomorse.org and correct some repetitive code by [@htlsmilework](https://github.com/htlsmilework) in [#42](https://github.com/dromara/dongle/pull/42)
- Decode the ascii85 z shortcut without truncating by [@youdie006](https://github.com/youdie006) in [#44](https://github.com/dromara/dongle/pull/44)
- perf(morse): Derive the reverse alphabet once instead of scanning it per symbol by [@darakanoit](https://github.com/darakanoit) in [#46](https://github.com/dromara/dongle/pull/46)
- Pad the ascii85 partial group without counting z shortcuts by [@youdie006](https://github.com/youdie006) in [#47](https://github.com/dromara/dongle/pull/47)
- fix(coding): encode and decode base58 and base62 streams as a whole by [@Shaisolaris](https://github.com/Shaisolaris) in [#48](https://github.com/dromara/dongle/pull/48)
- fix(keypair): correct SingMode test assertion and add explicit default by [@gouguolei](https://github.com/gouguolei) in [079efab](https://github.com/dromara/dongle/commit/079efab2892b66028898fe430d0649e41bc7302e)
- fix(keypair): accept externally generated keys instead of panicking by [@gouguolei](https://github.com/gouguolei) in [012269d](https://github.com/dromara/dongle/commit/012269d4b1b58d58d4f1df3b816d276084cc545d)
- test(keypair): cover error paths and key material helpers by [@gouguolei](https://github.com/gouguolei) in [12c3e11](https://github.com/dromara/dongle/commit/12c3e11bf317e7643f932d8e8505bf2a08c6067b)
- docs(readme): replace old badge with golangci-lint by [@gouguolei](https://github.com/gouguolei) in [0517244](https://github.com/dromara/dongle/commit/05172446a907de460cc6c867c6c7b9c3ccf89e46)
- docs(readme): replace old badge with golangci-lint by [@gouguolei](https://github.com/gouguolei) in [1487675](https://github.com/dromara/dongle/commit/1487675d98fba9e5238ca93acb1371be045151a6)
- test: Clean up redundant content and unused variables in the test code by [@gouguolei](https://github.com/gouguolei) in [372209d](https://github.com/dromara/dongle/commit/372209db32677f5b9e8bab6547354196d501c463)
- test(sm2): DER encoding error branch covering key formatting by [@gouguolei](https://github.com/gouguolei) in [6ad47b4](https://github.com/dromara/dongle/commit/6ad47b474792c1e13502a5a7fb0df7ab6bf2e920)
- refactor(keypair): Extract x509 Marshall function as a variable to support testing simulation by [@gouguolei](https://github.com/gouguolei) in [e314c99](https://github.com/dromara/dongle/commit/e314c992215bc824c8f645e19edc3f29560ddf54)
- refactor(crypto): Replace the ed25519 key serialization function with a local implementation by [@gouguolei](https://github.com/gouguolei) in [0769ea0](https://github.com/dromara/dongle/commit/0769ea0d969de33899ff629a5307e5758e8b2f86)
- refactor(rsa): Replace the standard library key serialization function with a custom implementation by [@gouguolei](https://github.com/gouguolei) in [2c9ad5a](https://github.com/dromara/dongle/commit/2c9ad5a7bc0ff1ea0b2957b910328c33d8c6b98e)
- refactor(crypto/rsa): Simplify function signatures and clean up redundant code by [@gouguolei](https://github.com/gouguolei) in [68dad92](https://github.com/dromara/dongle/commit/68dad927bbb23e6c75558a4777f30e206eb99697)
- docs(readme): Replace the golangci lit badge with the GitHub Actions status badge by [@gouguolei](https://github.com/gouguolei) in [e6f8039](https://github.com/dromara/dongle/commit/e6f80393874bed09d5d86419ed57bcdf6a52aa62)
- docs(readme): Replace the image resource reference from remote URL to local assets path by [@gouguolei](https://github.com/gouguolei) in [19bffd5](https://github.com/dromara/dongle/commit/19bffd59a533b482779a06257c5c94817724bca8)

:::

## [v1.2.3](https://github.com/dromara/dongle/compare/v1.2.2...v1.2.3) (2025-12-16)

### ✨ 新機能

- **RSA 鍵ペアが操作に必要な鍵だけを保持できるようになりました**：`RsaKeyPair` に `Type` フィールドと `SetType` メソッドを追加し、`KeyType` 型と `PublicKey`、`PrivateKey` 定数も新設しました。`NewStdEncrypter`、`NewStdDecrypter`、`NewStdSigner`、`NewStdVerifier` と対応するストリーム実装が鍵の種類で分岐するため、公開鍵だけを持つ鍵ペアでも暗号化と検証が、秘密鍵だけを持つ鍵ペアでも復号と署名ができます。公開鍵を署名側、秘密鍵を検証側にすることも可能です。`Type` が空の場合は操作ごとに適切な側へフォールバックし（暗号化と検証は `PublicKey`、復号と署名は `PrivateKey`）、既定のパディングは鍵形式に従います（`PKCS1` は `PKCS1v15`、`PKCS8` は暗号化に `OAEP`、署名に `PSS`）。署名に `OAEP`、暗号化に `PSS` を渡すと `UnsupportedPaddingSchemeError` を返します。Go 標準ライブラリが片方向しか公開していない PSS エンコードと MGF1 を含め、公開鍵・秘密鍵の両方向とすべてのパディングの組み合わせを `crypto/internal/rsa` に実装しました（by [@gouguoyin](https://github.com/gouguoyin) in [12ffe48](https://github.com/dromara/dongle/commit/12ffe48) [eb81cbc](https://github.com/dromara/dongle/commit/eb81cbc) [33ac684](https://github.com/dromara/dongle/commit/33ac684) [749b690](https://github.com/dromara/dongle/commit/749b690)）
- **`Sm2KeyPair` に `SetMode` を追加し、`CipherOrder` を `Sm2CipherMode` に改名**：暗号文の順序を指定する推奨方法が `SetMode` になり、`SetOrder` は既存の呼び出しがコンパイルできるよう薄いエイリアスとして残ります。型名の変更は `CipherOrder` を明示的に書いたコードにのみ影響し、引数名 `order` は全体で `mode` に統一されて鍵の順序という意味と混同されなくなりました（by [@gouguoyin](https://github.com/gouguoyin) in [858d8b8](https://github.com/dromara/dongle/commit/858d8b8) [3785a02](https://github.com/dromara/dongle/commit/3785a02) [6d30805](https://github.com/dromara/dongle/commit/6d30805) [56b6b15](https://github.com/dromara/dongle/commit/56b6b15)）

### 🔧 リファクタリング

- **`Sm2KeyPair` の `LoadPublicKey`、`LoadPrivateKey` を削除**：SM2 はファイルを自ら読み込む最後の鍵ペアで、呼び出し側は `fs.File` を渡す必要がありました。ファイルを自分で読み込んで `SetPublicKey` / `SetPrivateKey` にバイト列を渡す形になり、RSA、Ed25519 と揃いました（by [@gouguoyin](https://github.com/gouguoyin) in [e4d6e3c](https://github.com/dromara/dongle/commit/e4d6e3c)）
- **`crypto/sm2` を `encrypt.go`、`decrypt.go`、`sign.go`、`verify.go` に分割**し、内部ヘルパーを `EncryptWithPublicKey`、`DecryptWithPrivateKey`、`SignWithPrivateKey`、`VerifyWithPublicKey` に改名しました。どの鍵が必要かが呼び出し箇所で分かります。重複していた SM2 実装を削除し、補助関数を独立したファイルに分離、`priv` フィールドはパッケージ内の命名に合わせて `pri` に改名しました（by [@gouguoyin](https://github.com/gouguoyin) in [86819de](https://github.com/dromara/dongle/commit/86819de) [1602745](https://github.com/dromara/dongle/commit/1602745) [0dfd8ea](https://github.com/dromara/dongle/commit/0dfd8ea) [c0a45e4](https://github.com/dromara/dongle/commit/c0a45e4) [ccc968f](https://github.com/dromara/dongle/commit/ccc968f) [f876923](https://github.com/dromara/dongle/commit/f876923)）
- **Ed25519 の解析済み鍵をキャッシュ**：署名器と検証器は呼び出しごとに PEM を解析し、`crypto/keypair` にある解析ロジックと重複していました。現在は一度だけ解析してキャッシュし、重複コードを削除、パッケージを `ed25519.go`、`sign.go`、`verify.go` に分割しました（by [@gouguoyin](https://github.com/gouguoyin) in [0ed7ca5](https://github.com/dromara/dongle/commit/0ed7ca5)）
- **RC4 フォールバック経路の不要な cipher 生成を削除**：この分岐が生成した cipher は直ちに破棄されていました（by [@gouguoyin](https://github.com/gouguoyin) in [9320875](https://github.com/dromara/dongle/commit/9320875)）

::: details What's Changed (18)

- refactor(ed25519): Remove duplicate key parsing logic and use caching to improve performance by [@gouguoyin](https://github.com/gouguoyin) in [0ed7ca5](https://github.com/dromara/dongle/commit/0ed7ca5)
- refactor(rc4): Delete the redundant code for creating cipher in fallback by [@gouguoyin](https://github.com/gouguoyin) in [9320875](https://github.com/dromara/dongle/commit/9320875)
- chore(sm2): Remove redundant implementation and modularize the splitting function to independent files by [@gouguoyin](https://github.com/gouguoyin) in [86819de](https://github.com/dromara/dongle/commit/86819de)
- refactor(sm2): priv -> pri by [@gouguoyin](https://github.com/gouguoyin) in [f876923](https://github.com/dromara/dongle/commit/f876923)
- feat(rsa): Provide signature generation and verification methods based on public and private keys by [@gouguoyin](https://github.com/gouguoyin) in [749b690](https://github.com/dromara/dongle/commit/749b690)
- feat(keypair): Add key type definition to distinguish between public and private keys by [@gouguoyin](https://github.com/gouguoyin) in [12ffe48](https://github.com/dromara/dongle/commit/12ffe48)
- feat(rsa): Add a Type field in the RsaKeyPair structure to specify the key type by [@gouguoyin](https://github.com/gouguoyin) in [eb81cbc](https://github.com/dromara/dongle/commit/eb81cbc)
- feat(rsa): Add support for public key encryption and private key decryption by [@gouguoyin](https://github.com/gouguoyin) in [33ac684](https://github.com/dromara/dongle/commit/33ac684)
- refactor(sm2): Remove the CipherOrder type definition and replace it with a string constant by [@gouguoyin](https://github.com/gouguoyin) in [3785a02](https://github.com/dromara/dongle/commit/3785a02)
- refactor(sm2): Delete the 'LoadPublicKey' and 'LoadPrivateKey' methods by [@gouguoyin](https://github.com/gouguoyin) in [e4d6e3c](https://github.com/dromara/dongle/commit/e4d6e3c)
- refactor(sm2): Decrypt -> DecryptWithPrivateKey by [@gouguoyin](https://github.com/gouguoyin) in [1602745](https://github.com/dromara/dongle/commit/1602745)
- refactor(sm2): Encrypt -> EncryptWithPublicKey by [@gouguoyin](https://github.com/gouguoyin) in [0dfd8ea](https://github.com/dromara/dongle/commit/0dfd8ea)
- refactor(sm2): Sign -> SignWithPrivateKey by [@gouguoyin](https://github.com/gouguoyin) in [c0a45e4](https://github.com/dromara/dongle/commit/c0a45e4)
- refactor(sm2): Verify -> VerifyWithPublicKey by [@gouguoyin](https://github.com/gouguoyin) in [ccc968f](https://github.com/dromara/dongle/commit/ccc968f)
- refactor(sm2): Change the function parameter name from 'order' to 'mode' by [@gouguoyin](https://github.com/gouguoyin) in [6d30805](https://github.com/dromara/dongle/commit/6d30805)
- feat(crypto): Add `SetMode` method to replace the existing `SetOrder` method by [@gouguoyin](https://github.com/gouguoyin) in [858d8b8](https://github.com/dromara/dongle/commit/858d8b8)
- refactor(sm2): Rename the Order parameter to Mode by [@gouguoyin](https://github.com/gouguoyin) in [56b6b15](https://github.com/dromara/dongle/commit/56b6b15)
- docs(utils): Update Int2Bytes function comments by [@gouguoyin](https://github.com/gouguoyin) in [3d22896](https://github.com/dromara/dongle/commit/3d22896)

:::

## [v1.2.2](https://github.com/dromara/dongle/compare/v1.2.1...v1.2.2) (2025-12-08)

### ✨ 新機能

- **チェーン API に SM2 の署名と検証を追加**：`Signer.BySm2` と `Verifier.BySm2` を追加し、標準処理とストリーム処理の両方で利用できます。SM2 が RSA、Ed25519 と同じように、同じチェーン上で秘密鍵による署名と公開鍵による検証を行えます。`Sm2KeyPair.SetUID` は ZA の計算に混ぜるユーザー識別子を設定し、未設定時は `1234567812345678` のままです。検証時に署名が空の場合は曲線演算に入る前に `EmptySignatureError` を返します（by [@gouguoyin](https://github.com/gouguoyin) in [b72066e](https://github.com/dromara/dongle/commit/b72066ef089fd58727d321b575b9d16d87d9f211) [0382cd6](https://github.com/dromara/dongle/commit/0382cd6) [39d00c3](https://github.com/dromara/dongle/commit/39d00c3)）
- **RSA のパディング方式を選択可能に**：`RsaPaddingScheme` 型が `PKCS1v15`、`OAEP`、`PSS` を提供し、`SetPadding` で指定します。`PKCS1v15` は暗号化と署名の両方に、`OAEP` は暗号化のみで `SetHash` によるハッシュ指定が必要、`PSS` は署名のみに使えます。未指定の場合は鍵形式に従い、`PKCS1` の鍵は `PKCS1v15`、`PKCS8` の鍵は `OAEP` にフォールバックします。未対応の組み合わせは標準ライブラリの曖昧なエラーではなく `UnsupportedPaddingSchemeError` を返します（by [@gouguoyin](https://github.com/gouguoyin) in [d1734dc](https://github.com/dromara/dongle/commit/d1734dc) [b4173be](https://github.com/dromara/dongle/commit/b4173be) [d08e5fc](https://github.com/dromara/dongle/commit/d08e5fc)）
- **鍵と署名のエラー型を細分化**：`EmptyPrivateKeyError`、`EmptyFormatError`、`UnsupportedKeyFormatError`、`EmptyPaddingError`、`UnsupportedPaddingSchemeError`、`EmptySignatureError` が単一の包括的なエラーを置き換え、鍵の欠落と鍵の破損を区別できるようになりました（by [@gouguoyin](https://github.com/gouguoyin) in [856dd51](https://github.com/dromara/dongle/commit/856dd51)）

### 🐛 修正

- **秘密鍵が PKCS#8 形式のときに PKCS#1 v1.5 の暗号文を復号できない問題を修正**（[#39](https://github.com/dromara/dongle/issues/39)）：`Format` が `PKCS8` でパディングを明示しない場合、復号は OAEP にフォールバックしていたため、JSEncrypt や PHP の `openssl_*` が既定のパディングで生成した暗号文は `crypto/rsa: decryption error` になりました。同じ暗号文を PHP 自身は復号できていました。現在は `SetPadding` でパディングを指定でき、報告で使われた鍵ペアは回帰テストとして残しています（by [@gouguoyin](https://github.com/gouguoyin) in [27c69f6](https://github.com/dromara/dongle/commit/27c69f6)）
- **RSA 検証の冗長な署名長チェックを削除**：このチェックは `rsa.Verify*` が検証する前に他ライブラリの正当な署名を拒否していました。標準ライブラリは不正な長さの署名に対して明確なエラーを返します（by [@gouguoyin](https://github.com/gouguoyin) in [faa99bb](https://github.com/dromara/dongle/commit/faa99bb)）

### ⚡ パフォーマンス

- **モールスのエンコード・デコードで結果返却時のコピーを 1 回削減**：`[]byte(builder.String())` を `utils.String2Bytes` に置き換え、`builder` のバッファを再利用して余分なコピーをなくしました。出力自体が支配的な大きめのデータで効果があります（by [@gouguoyin](https://github.com/gouguoyin) in [10d2eb0](https://github.com/dromara/dongle/commit/10d2eb0)）

### 🔧 リファクタリング

- **鍵形式と暗号文順序の型をアルゴリズム別に改名**：`KeyFormat` を `RsaKeyFormat`、`CipherOrder` を `Sm2CipherOrder` に変更し、すべてのアルゴリズムに適用されるかのような汎用的な名前をなくしました。`NoSignatureError` は `EmptySignatureError`、`UnsupportedPemTypeError` は `UnsupportedKeyFormatError`、`Ed25519KeyPair.Sign` は `Signature` になりました（by [@gouguoyin](https://github.com/gouguoyin) in [37d5a1a](https://github.com/dromara/dongle/commit/37d5a1a) [ac77cf7](https://github.com/dromara/dongle/commit/ac77cf7) [6135756](https://github.com/dromara/dongle/commit/6135756) [8a6ea39](https://github.com/dromara/dongle/commit/8a6ea39)）
- **RSA の暗号化・復号・署名・検証の経路を書き直し**：各操作は暗号化器、復号器、署名器、検証器の生成時にパディングを一度だけ決定して分岐するため、`PSS` を暗号化に使う指定や `OAEP` のハッシュ不足はストリーム処理の途中ではなく生成時に報告されます（by [@gouguoyin](https://github.com/gouguoyin) in [d08e5fc](https://github.com/dromara/dongle/commit/d08e5fc)）
- **ストリーム復号器のフィールド名を変更**：`decrypted` を `buffer`、`pos` を `position` に変更し、3DES、AES、Blowfish、DES、Tea、XTea、Twofish、SM4、Salsa20 に適用しました。あわせて 3DES ストリーム復号器の入力分割処理を簡素化しています（by [@gouguoyin](https://github.com/gouguoyin) in [114d3be](https://github.com/dromara/dongle/commit/114d3be) [efefe59](https://github.com/dromara/dongle/commit/efefe59) [e66e508](https://github.com/dromara/dongle/commit/e66e508) [ba303e7](https://github.com/dromara/dongle/commit/ba303e7) [4d93579](https://github.com/dromara/dongle/commit/4d93579) [e0b9f3b](https://github.com/dromara/dongle/commit/e0b9f3b) [5f311b4](https://github.com/dromara/dongle/commit/5f311b4) [426506a](https://github.com/dromara/dongle/commit/426506a) [f375496](https://github.com/dromara/dongle/commit/f375496) [ce101f1](https://github.com/dromara/dongle/commit/ce101f1)）
- **Ed25519 の `StdSigner`、`StdVerifier` が鍵ペアを値で保持**：ポインタではなく値で保持するため、生成後に外部で鍵ペアを変更しても実行中の操作に影響しません。あわせて Ed25519 のエラー型を簡素化しました（by [@gouguoyin](https://github.com/gouguoyin) in [b5cd502](https://github.com/dromara/dongle/commit/b5cd502) [225b70f](https://github.com/dromara/dongle/commit/225b70f)）
- **`mock`、`utils` を `internal` に移動**：テスト補助パッケージとゼロコピーのヘルパーはモジュール外部からインポートできなくなり、SM4 の実装は `crypto/internal/sm4` に移りました（by [@gouguoyin](https://github.com/gouguoyin) in [ef82486](https://github.com/dromara/dongle/commit/ef82486) [fe841a7](https://github.com/dromara/dongle/commit/fe841a7)）
- **内部の `sm2curve` パッケージを `sm2` に改名**し、`stdAsn1` エイリアスを他のファイルで使われている `encodingAsn1` に統一しました（by [@gouguoyin](https://github.com/gouguoyin) in [14e9818](https://github.com/dromara/dongle/commit/14e9818) [cf69603](https://github.com/dromara/dongle/commit/cf69603)）
- **テストを簡素化**：`internal/mock` の `mock.File` がテストごとに実装していた reader モックを置き換え、すべてのテストで開いたファイルを閉じるようにし、中国語のコメントを英語に統一しました（by [@gouguoyin](https://github.com/gouguoyin) in [6b021d7](https://github.com/dromara/dongle/commit/6b021d7) [3ea3710](https://github.com/dromara/dongle/commit/3ea3710) [bd8b1b3](https://github.com/dromara/dongle/commit/bd8b1b3) [7fb2ddc](https://github.com/dromara/dongle/commit/7fb2ddc) [9a4b693](https://github.com/dromara/dongle/commit/9a4b693) [2cab5e7](https://github.com/dromara/dongle/commit/2cab5e7) [bbc4123](https://github.com/dromara/dongle/commit/bbc4123) [ee77460](https://github.com/dromara/dongle/commit/ee77460)）

### 📝 ドキュメント

- **鍵ペアパッケージのドキュメントと RSA の使い方を更新**し、新しいパディング方式と鍵形式の型について補足しました（by [@gouguoyin](https://github.com/gouguoyin) in [dafc7cf](https://github.com/dromara/dongle/commit/dafc7cf) [b765056](https://github.com/dromara/dongle/commit/b765056) [399de93](https://github.com/dromara/dongle/commit/399de93)）

::: details What's Changed (38)

- refactor(sm2curve): ParseDerPublicKey -> ParseBitStringPublicKey, ParseDerPrivateKey -> ParseBitStringPrivateKey by [@gouguoyin](https://github.com/gouguoyin) in [faac61c](https://github.com/dromara/dongle/commit/faac61c) [81224c4](https://github.com/dromara/dongle/commit/81224c4)
- refactor(internal): Move `mock` and `utils` packages to `internal` by [@gouguoyin](https://github.com/gouguoyin) in [ef82486](https://github.com/dromara/dongle/commit/ef82486)
- refactor(sm2curve): stdAsn1 -> encodingAsn1 by [@gouguoyin](https://github.com/gouguoyin) in [cf69603](https://github.com/dromara/dongle/commit/cf69603)
- docs: Remove document comments for package by [@gouguoyin](https://github.com/gouguoyin) in [43a793b](https://github.com/dromara/dongle/commit/43a793b)
- test(coding): Change Chinese annotations to English by [@gouguoyin](https://github.com/gouguoyin) in [ee77460](https://github.com/dromara/dongle/commit/ee77460)
- refactor(crypto/3des): Optimize the data processing logic of the streaming decryptor by [@gouguoyin](https://github.com/gouguoyin) in [ce101f1](https://github.com/dromara/dongle/commit/ce101f1)
- refactor: decrypted -> buffer, pos -> position in AES, Blowfish, DES, Tea, XTea, Twofish, SM4 and Salsa20 by [@gouguoyin](https://github.com/gouguoyin) in [114d3be](https://github.com/dromara/dongle/commit/114d3be) [efefe59](https://github.com/dromara/dongle/commit/efefe59) [e66e508](https://github.com/dromara/dongle/commit/e66e508) [ba303e7](https://github.com/dromara/dongle/commit/ba303e7) [4d93579](https://github.com/dromara/dongle/commit/4d93579) [e0b9f3b](https://github.com/dromara/dongle/commit/e0b9f3b) [5f311b4](https://github.com/dromara/dongle/commit/5f311b4) [426506a](https://github.com/dromara/dongle/commit/426506a) [f375496](https://github.com/dromara/dongle/commit/f375496)
- refactor(ed25519): Modify the keypair field in StdSigner and StdVerifier to a value type instead of a pointer type by [@gouguoyin](https://github.com/gouguoyin) in [b5cd502](https://github.com/dromara/dongle/commit/b5cd502)
- refactor(ed25519): Simplify error types and optimize error message formats by [@gouguoyin](https://github.com/gouguoyin) in [225b70f](https://github.com/dromara/dongle/commit/225b70f)
- chore(crypto): NoSignatureError -> EmptySignatureError by [@gouguoyin](https://github.com/gouguoyin) in [6135756](https://github.com/dromara/dongle/commit/6135756)
- fix(rsa): Remove redundant signature length check by [@gouguoyin](https://github.com/gouguoyin) in [faa99bb](https://github.com/dromara/dongle/commit/faa99bb)
- fix(rsa): Fix PKCS8 format key decryption failure (issue [#39](https://github.com/dromara/dongle/issues/39)) by [@gouguoyin](https://github.com/gouguoyin) in [27c69f6](https://github.com/dromara/dongle/commit/27c69f6)
- refactor(crypto): Sign -> Signature, UnsupportedPemTypeError -> UnsupportedKeyFormatError by [@gouguoyin](https://github.com/gouguoyin) in [8a6ea39](https://github.com/dromara/dongle/commit/8a6ea39)
- feat(crypto): Add multiple types of key and signature related errors by [@gouguoyin](https://github.com/gouguoyin) in [856dd51](https://github.com/dromara/dongle/commit/856dd51)
- feat(crypto): Introduce PaddingScheme type to support multiple RSA filling schemes by [@gouguoyin](https://github.com/gouguoyin) in [d1734dc](https://github.com/dromara/dongle/commit/d1734dc)
- feat(rsa): Add the SetPadding method by [@gouguoyin](https://github.com/gouguoyin) in [b4173be](https://github.com/dromara/dongle/commit/b4173be)
- refactor(rsa): Refactoring RSA encryption, decryption, signature verification logic by [@gouguoyin](https://github.com/gouguoyin) in [d08e5fc](https://github.com/dromara/dongle/commit/d08e5fc)
- feat(sm2curve): Implement SM2 algorithm signature and verification function by [@gouguoyin](https://github.com/gouguoyin) in [0382cd6](https://github.com/dromara/dongle/commit/0382cd6)
- feat(sm2): Add SetUID method by [@gouguoyin](https://github.com/gouguoyin) in [39d00c3](https://github.com/dromara/dongle/commit/39d00c3)
- refactor(crypto/sm2): Remove unused error types by [@gouguoyin](https://github.com/gouguoyin) in [7bc33cd](https://github.com/dromara/dongle/commit/7bc33cd)
- feat(crypto): Add SM2 signature and verification function by [@gouguoyin](https://github.com/gouguoyin) in [b72066e](https://github.com/dromara/dongle/commit/b72066ef089fd58727d321b575b9d16d87d9f211)
- refactor(sm2): Remove redundant auxiliary functions and dependencies by [@gouguoyin](https://github.com/gouguoyin) in [bc5962c](https://github.com/dromara/dongle/commit/bc5962c)
- docs(keypair): Update the documentation for the key pair package by [@gouguoyin](https://github.com/gouguoyin) in [dafc7cf](https://github.com/dromara/dongle/commit/dafc7cf)
- chore(rsa): Move the RSA key format and padding scheme type to the `rsa.go` file by [@gouguoyin](https://github.com/gouguoyin) in [88ba1d6](https://github.com/dromara/dongle/commit/88ba1d6)
- chore(sm2): Move the SM2 cipher order from `keypair.go` to `sm2.go` file by [@gouguoyin](https://github.com/gouguoyin) in [ac77cf7](https://github.com/dromara/dongle/commit/ac77cf7)
- chore(test): KeyFormat -> RsaKeyFormat by [@gouguoyin](https://github.com/gouguoyin) in [37d5a1a](https://github.com/dromara/dongle/commit/37d5a1a)
- refactor(sm2): Rename the sm2curve package to sm2 and update related references by [@gouguoyin](https://github.com/gouguoyin) in [14e9818](https://github.com/dromara/dongle/commit/14e9818)
- refactor: Modify the cipher field type of the encryption and decryption structures in 3DES, AES, Blowfish, ChaCha20, ChaCha20-Poly1305, DES, Salsa20, Tea, XTea, Twofish and SM4 by [@gouguoyin](https://github.com/gouguoyin) in [d7d72be](https://github.com/dromara/dongle/commit/d7d72be) [af560ef](https://github.com/dromara/dongle/commit/af560ef) [582d5d8](https://github.com/dromara/dongle/commit/582d5d8) [38587f9](https://github.com/dromara/dongle/commit/38587f9) [5b780d4](https://github.com/dromara/dongle/commit/5b780d4) [4c87f81](https://github.com/dromara/dongle/commit/4c87f81) [b0f2e45](https://github.com/dromara/dongle/commit/b0f2e45) [ec29312](https://github.com/dromara/dongle/commit/ec29312) [8435966](https://github.com/dromara/dongle/commit/8435966) [1b2be97](https://github.com/dromara/dongle/commit/1b2be97) [ab4ee6d](https://github.com/dromara/dongle/commit/ab4ee6d)
- test(sm2): []byte{} -> {} by [@gouguoyin](https://github.com/gouguoyin) in [48834cc](https://github.com/dromara/dongle/commit/48834cc)
- refactor(sm4): Migration of SM4 implementation from crypto/sm4/core.go to crypto/internal/sm4/sm4.go by [@gouguoyin](https://github.com/gouguoyin) in [fe841a7](https://github.com/dromara/dongle/commit/fe841a7)
- refactor(morse): Optimize the conversion method from string to byte slice by [@gouguoyin](https://github.com/gouguoyin) in [10d2eb0](https://github.com/dromara/dongle/commit/10d2eb0)
- test(coding): Simplify code using mock.File by [@gouguoyin](https://github.com/gouguoyin) in [6b021d7](https://github.com/dromara/dongle/commit/6b021d7)
- test(crypto): Simplify code using mock.File by [@gouguoyin](https://github.com/gouguoyin) in [3ea3710](https://github.com/dromara/dongle/commit/3ea3710)
- test(hash): Simplify code using mock.File by [@gouguoyin](https://github.com/gouguoyin) in [bd8b1b3](https://github.com/dromara/dongle/commit/bd8b1b3)
- test(sm2): Simplify code using mock.File by [@gouguoyin](https://github.com/gouguoyin) in [7fb2ddc](https://github.com/dromara/dongle/commit/7fb2ddc)
- test: Add defer file.Close() to all test functions to avoid resource leakage by [@gouguoyin](https://github.com/gouguoyin) in [9a4b693](https://github.com/dromara/dongle/commit/9a4b693) [2cab5e7](https://github.com/dromara/dongle/commit/2cab5e7) [bbc4123](https://github.com/dromara/dongle/commit/bbc4123)
- docs(crypto): Update RSA key pair document comments by [@gouguoyin](https://github.com/gouguoyin) in [b765056](https://github.com/dromara/dongle/commit/b765056)
- docs(rsa): Update RSA key pair usage instructions by [@gouguoyin](https://github.com/gouguoyin) in [399de93](https://github.com/dromara/dongle/commit/399de93)

:::

## [v1.2.1](https://github.com/dromara/dongle/compare/v1.2.0...v1.2.1) (2025-11-24)

### ✨ 新機能

- `Sm2` 非対称楕円曲線暗号化アルゴリズムに `BIT_STRING` 形式キーの直接解析サポートを追加

### 🐛 修正

- `Sm2` 非対称楕円曲線暗号化アルゴリズムの `wNAF` アルゴリズムエラーによる一部の復号化失敗のバグを修正

### ⚡ パフォーマンス

- `Sm2` 非対称楕円曲線暗号化アルゴリズムの曲線フィールド要素演算実装を最適化

### 🔧 リファクタリング

- テストループ構文を簡素化、`for` ループから `range` ループに変更

::: details What's Changed (12)

- refactor(sm2curve): pointFelem -> pointField by [@gouguoyin](https://github.com/gouguoyin) in [eb6878e](https://github.com/dromara/dongle/commit/eb6878e707c33d2e46fe7262b4441a2773909659)
- test(sm2): Change the declaration method of empty byte slices from literal to var declaration by [@gouguoyin](https://github.com/gouguoyin) in [38a86c8](https://github.com/dromara/dongle/commit/38a86c826ea23232d80b5a4cbf3e949bacb29dd7)
- style(sm2curve): Add necessary comments by [@gouguoyin](https://github.com/gouguoyin) in [27497c7](https://github.com/dromara/dongle/commit/27497c7d310d6787660a5667aeb4528a76b55508)
- Potential fix for code scanning alert no. 1: Workflow does not contain permissions (#33) by kuafuRace in [9bab6c9](https://github.com/dromara/dongle/commit/9bab6c9a21fd689bf1bb7e2458a383a5c5cb0081)
- Add direct parsing of hexadecimal key pairs for SM2 (#32) by [@WebChang](https://github.com/WebChang) in [a4509b6](https://github.com/dromara/dongle/commit/a4509b6d180017715e156f6f0bb207bb109dbfab)
- Fix the wNAF algorithm (#36) by [@WebChang](https://github.com/WebChang) in [73911e8](https://github.com/dromara/dongle/commit/73911e8175fba86a530fc7b7abbbf7f0a1185d2b)
- fix(crypto): Introduce a rewritable parseDerPrivatKeyFunc variable to support test simulation by [@gouguoyin](https://github.com/gouguoyin) in [d61fe04](https://github.com/dromara/dongle/commit/d61fe04431fc38d502db88ba574a610b8095f07d)
- test(sm2): Improve unit testing coverage to 100% by [@gouguoyin](https://github.com/gouguoyin) in [7b2ddf3](https://github.com/dromara/dongle/commit/7b2ddf39c577b8bd3139d2ff94c9c60132e0a288)
- chore(version): Update version number to 1.2.1 by [@gouguoyin](https://github.com/gouguoyin) in [31d1ee7](https://github.com/dromara/dongle/commit/31d1ee75be877504b1423cb16f2e4594c432f757)
- Add issue unit test (#38) by [@WebChang](https://github.com/WebChang) in [b91161c](https://github.com/dromara/dongle/commit/b91161c167b9ca550a2ba6790eb85374c2337fe5)
- fix(sm2curve): Fix SM2 curve domain element subtraction and borrowing processing by [@gouguoyin](https://github.com/gouguoyin) in [1164b55](https://github.com/dromara/dongle/commit/1164b556a761c33b286884d58805190842512d28)
- fix(sm2): Add issue #34 unit test by [@gouguoyin](https://github.com/gouguoyin) in [b86b4dd](https://github.com/dromara/dongle/commit/b86b4ddbba730caa15280b1c0704ddcefb9ba3bf)

:::

## [v1.2.0](https://github.com/dromara/dongle/compare/v1.1.8...v1.2.0) (2025-11-11)

### ✨ 新機能

- `RSAKeyPair` 構造体に `FormatPublicKey` および `FormatPrivateKey` メソッドを追加、`base64` エンコードされた `der` 形式の `RSA` 公開鍵と秘密鍵を `pem` 形式にフォーマット
- `Ed25519KeyPair` 構造体に `FormatPublicKey` および `FormatPrivateKey` メソッドを追加、`base64` エンコードされた `der` 形式の `Ed25519` 公開鍵と秘密鍵を `pem` 形式にフォーマット
- `RSAKeyPair` 構造体に `CompressPublicKey` および `CompressPrivateKey` メソッドを追加、`pem` 形式の `RSA` 公開鍵と秘密鍵を `base64` エンコードされた `der` 形式に圧縮
- `Ed25519KeyPair` 構造体に `CompressPublicKey` および `CompressPrivateKey` メソッドを追加、`pem` 形式の `Ed25519` 公開鍵と秘密鍵を `base64` エンコードされた `der` 形式に圧縮
- `Sm2` 非対称楕円曲線暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

### ⚡ パフォーマンス

- エンコーダーとデコーダーのパフォーマンスを最適化、読み取りバッファを再利用し、メモリ割り当てとコピーを削減

### 🔧 リファクタリング

- `RSAKeyPair` 構造体の `LoadPublicKey` および `LoadPrivateKey` メソッドを削除
- `Ed25519KeyPair` 構造体の `LoadPublicKey` および `LoadPrivateKey` メソッドを削除
- `RSAKeyPair` 構造体の `GenKeyPair`、`SetPublicKey`、`SetPrivateKey` メソッドを返り値なしから `error` を返すように変更
- `Ed25519KeyPair` 構造体の `GenKeyPair`、`SetPublicKey`、`SetPrivateKey` メソッドを返り値なしから `error` を返すように変更

::: details What's Changed (25)

- chore(dongle): Update package meta and version number by [@gouguoyin](https://github.com/gouguoyin) in [ab46cdb](https://github.com/dromara/dongle/commit/ab46cdba1a77716446185e9aaa5beb8382ec09d3)
- feat(mock): Add `Error WriteAfterN` struct, which supports returning an error after a specified number of writes by [@gouguoyin](https://github.com/gouguoyin) in [a92350f](https://github.com/dromara/dongle/commit/a92350fa223e94618ae420e19d6f96d8267d9f39)
- test(style): Unify unit test case Name by [@gouguoyin](https://github.com/gouguoyin) in [fda8e09](https://github.com/dromara/dongle/commit/fda8e09bc8d963a4d447c657e5d3033a0a8acda3)
- fix(cipher): Change the return value of empty input from `src` to `[]byte{}` by [@gouguoyin](https://github.com/gouguoyin) in [81d8e29](https://github.com/dromara/dongle/commit/81d8e29929a6f6992d4b0ac86c4beb1e6fe277d5)
- feat(sm2curve): Implement SM2-P-256 elliptic curve and ASN.1 encoding and decoding for sm2 by [@gouguoyin](https://github.com/gouguoyin) in [8120c6b](https://github.com/dromara/dongle/commit/8120c6b152546dfa33d4dcd993c133fe744295e5)
- perf(base32): Optimize the performance of streaming codecs by [@gouguoyin](https://github.com/gouguoyin) in [df8bc9f](https://github.com/dromara/dongle/commit/df8bc9f6e50d05e1c0eca9dd721ad58ce88763ed)
- perf(base45):Optimize the performance of base45 encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [15669d5](https://github.com/dromara/dongle/commit/15669d50337ce1aca23f8ea39deefb158c90b9b8)
- refactor(base58): Optimize the implementation of stream encoders and decoders by [@gouguoyin](https://github.com/gouguoyin) in [70b7b7b](https://github.com/dromara/dongle/commit/70b7b7b1b8c0093e0e15e53d10a1b815638ae4d3)
- refactor(base62): Optimize the implementation of stream encoders and decoders by [@gouguoyin](https://github.com/gouguoyin) in [2de952d](https://github.com/dromara/dongle/commit/2de952db3017c15daa6aec192b4ba3a2c9c14884)
- perf(base64): Optimize the implementation of stream encoders and decoders by [@gouguoyin](https://github.com/gouguoyin) in [94575a1](https://github.com/dromara/dongle/commit/94575a1ae2828fa2db18a093c49d61ed1b11d7a3)
- refactor(base85): Optimize the implementation of stream encoders and decoders by [@gouguoyin](https://github.com/gouguoyin) in [5c03d1a](https://github.com/dromara/dongle/commit/5c03d1aff0ab46a8e32f88d34f7e0bf5e07151d2)
- perf(base91): Optimize encoding and decoding performance by [@gouguoyin](https://github.com/gouguoyin) in [bcff90c](https://github.com/dromara/dongle/commit/bcff90cbb6a0a1cd599f1e24241767973b0b2f66)
- perf(base100): Optimize the implementation of stream encoders and decoders by [@gouguoyin](https://github.com/gouguoyin) in [058877c](https://github.com/dromara/dongle/commit/058877c6cba305e46fa3f26b442bc1a355296619)
- refactor(morse): Optimize the buffer usage of streaming decoders by [@gouguoyin](https://github.com/gouguoyin) in [a52a536](https://github.com/dromara/dongle/commit/a52a53613195b3a5aa7234d758db50be4506a02f)
- feat(unicode): Optimize the buffer usage of streaming decoders by [@gouguoyin](https://github.com/gouguoyin) in [dd27319](https://github.com/dromara/dongle/commit/dd273190483467df9a12ba1daf3bf763b45627be)
- feat(crypto): Add FormatPublicKey,FormatPrivateKey, CompressPublicKey, CompressPrivateKey methods by [@gouguoyin](https://github.com/gouguoyin) in [e947625](https://github.com/dromara/dongle/commit/e947625c504616a951e23c5cd8c4707a070db5b1)
- feat(crypto): Add EmptyPublicKeyError and EmptyPrivateKeyError by [@gouguoyin](https://github.com/gouguoyin) in [c844db5](https://github.com/dromara/dongle/commit/c844db52c9dd502b81a7cd9ab50878772b7e079a)
- refactor(keypair): Add CipherOrder type to control the order of SM2 ciphertext components by [@gouguoyin](https://github.com/gouguoyin) in [e3d8df9](https://github.com/dromara/dongle/commit/e3d8df985f620b72066dc355b20b7f5497c66e20)
- feat(sm2): Add support for SM2 asymmetric elliptic curve encryption algorithm by [@gouguoyin](https://github.com/gouguoyin) in [dfa2a45](https://github.com/dromara/dongle/commit/dfa2a4506320d135d34cb5e439b9e32bffe43864)
- perf(md2): Optimize the performance of MD2 hash algorithm by [@gouguoyin](https://github.com/gouguoyin) in [380718a](https://github.com/dromara/dongle/commit/380718aa3c175ee828b3583fb745db47eb306602)
- perf(sm3): Optimize the performance of SM3 hash algorithm by [@gouguoyin](https://github.com/gouguoyin) in [9b1e3ed](https://github.com/dromara/dongle/commit/9b1e3ed2d226ee4bc99e104438702ca9b1233ef1)
- docs(readme): Add playground link url by [@gouguoyin](https://github.com/gouguoyin) in [c4fac75](https://github.com/dromara/dongle/commit/c4fac753e096f3c9e3f3793eef7c1f82154c01eb)
- docs: Update the annotation explanation in AES symmetric encryption algorithm by [@gouguoyin](https://github.com/gouguoyin) in [4adf429](https://github.com/dromara/dongle/commit/4adf42915b1b1ff7897c0f7cdb83c2513ed747da)
- refactor(sm2curve): Refactor the SM2 curve implementation to improve performance and maintainability by [@gouguoyin](https://github.com/gouguoyin) in [10eefe2](https://github.com/dromara/dongle/commit/10eefe2cc3d35fa9e366c77170aed72b36fa6472)
- refactor(crypto): MarshalPKCS8 -> MarshalPKCS8PrivateKey, MarshalSPKI ->MarshalSPKIPublicKey by [@gouguoyin](https://github.com/gouguoyin) in [ef63d93](https://github.com/dromara/dongle/commit/ef63d938c9a84c2ead50dbbe716e0cdc5ffade9a)

:::

## [v1.1.8](https://github.com/dromara/dongle/compare/v1.1.7...v1.1.8) (2025-11-05)

### ✨ 新機能

- `Unicode` エンコード/デコードサポートを追加（標準処理とストリーム処理を含む）
- 対称ブロック暗号化アルゴリズムに `TBC` パディングモードサポートを追加

### 🐛 修正

- `*RsaKeyPair.formatPublicKey` および `*RsaKeyPair.formatPrivateKey` による鍵のフォーマット失敗のバグを修正
- `*Ed25519KeyPair.formatPublicKey` および `*Ed25519KeyPair.formatPrivateKey` による鍵のフォーマット失敗のバグを修正
- 復号化時にエンコードされた暗号文のデコードが失敗した場合、エラーを取得できないバグを修正

### 🔧 リファクタリング

- 対称ブロック暗号化アルゴリズムのデフォルトパディングモードを `PKCS7` から `No` に変更

::: details What's Changed (36)

- chore(version): Update version number to `1.1.8` by [@gouguoyin](https://github.com/gouguoyin) in [3bfd036](https://github.com/dromara/dongle/commit/3bfd0364a4454fe734856ba156ce83ab44228782)
- feat(crypto): Add TBC padding mode support by [@gouguoyin](https://github.com/gouguoyin) in [304629d](https://github.com/dromara/dongle/commit/304629d9516ae5abbfd6d12545129ef0f9db3666)
- feat(unicode): Add `Unicode` encoding and decoding support by [@gouguoyin](https://github.com/gouguoyin) in [d174cd8](https://github.com/dromara/dongle/commit/d174cd8d4fd822cdc4fb32cf765472c71c3333cf)
- ci(test): Add support for Windows testing environment by [@gouguoyin](https://github.com/gouguoyin) in [da9ec1e](https://github.com/dromara/dongle/commit/da9ec1e26429705feb1d47098facffa90018e5fc)
- fix(hash): Add checks for h.Error by [@gouguoyin](https://github.com/gouguoyin) in [c044908](https://github.com/dromara/dongle/commit/c044908db685798416720fef48299f51f90e418f)
- fix(decoder): Add checks for d.Error by [@gouguoyin](https://github.com/gouguoyin) in [18041a3](https://github.com/dromara/dongle/commit/18041a31e7dc5e1b30f6ad020d9aeb3c60fafecf)
- fix(encoder): Add checks for e.Error by [@gouguoyin](https://github.com/gouguoyin) in [f97a481](https://github.com/dromara/dongle/commit/f97a4817f69e956853627a6be1d0e63d8133c065)
- feat(unicode): Add `Unicode` encoding/decoding support by [@gouguoyin](https://github.com/gouguoyin) in [8e1c38c](https://github.com/dromara/dongle/commit/8e1c38cf61a668b193f919dbf167b4a63459b102)
- feat(crypto): Add custom nonce length support for `GCM` mode by [@gouguoyin](https://github.com/gouguoyin) in [5cdaac8](https://github.com/dromara/dongle/commit/5cdaac8e13df44049ecd138ae75cd3aa486a5678)
- fix(signer): Add checks for s.Error by [@gouguoyin](https://github.com/gouguoyin) in [f0f2bc2](https://github.com/dromara/dongle/commit/f0f2bc2fb20a626ec0ed5fb04d44dafb3a1e4a33)
- fix(crypto): Fix signature decoding error handling by [@gouguoyin](https://github.com/gouguoyin) in [4107901](https://github.com/dromara/dongle/commit/4107901cd4c5b6dc25ce062e540df14a13e93ee3)
- fix(crypto): Fix ciphertext decoding error handling by [@gouguoyin](https://github.com/gouguoyin) in [763afd8](https://github.com/dromara/dongle/commit/763afd8cfd1875dcc0ecad5c8cf417c531347768)
- refactor(crypto): Change the default padding mode from `PKCS7` to `No` by [@gouguoyin](https://github.com/gouguoyin) in [00bd32b](https://github.com/dromara/dongle/commit/00bd32b30c67e2dae565fe164205bc03443c5536)
- feat(crypto/cipher): Optimize the block size check in CBC mode by [@gouguoyin](https://github.com/gouguoyin) in [781f292](https://github.com/dromara/dongle/commit/781f2922624e9b68edbc21f45fbfee3b686a41b8)
- refactor(cipher): Simplify the error handling using switch by [@gouguoyin](https://github.com/gouguoyin) in [a0abcf5](https://github.com/dromara/dongle/commit/a0abcf548cd85e9a74e706d2a29521df84c3fe26)
- refactor(cipher): InvalidSrcError -> InvalidPlaintextError by [@gouguoyin](https://github.com/gouguoyin) in [2677ffc](https://github.com/dromara/dongle/commit/2677ffc9b656c1540916cddb67ef4044442ffb68)
- test(des): Remove redundant decryption error test cases by [@gouguoyin](https://github.com/gouguoyin) in [72c39cd](https://github.com/dromara/dongle/commit/72c39cdb18d9eb5a7c36289ac5e644ac06b74b68)
- test(aes): Remove redundant decryption error test cases by [@gouguoyin](https://github.com/gouguoyin) in [36807d5](https://github.com/dromara/dongle/commit/36807d5998a9b7386945954ae137115d299b5253)
- test(sm4): Remove padding settings by [@gouguoyin](https://github.com/gouguoyin) in [7cdf2b5](https://github.com/dromara/dongle/commit/7cdf2b5bc061bfaf97733787bb6fb975a9c652e3)
- feat(crypto): Remove padding setting by [@gouguoyin](https://github.com/gouguoyin) in [bac1c2a](https://github.com/dromara/dongle/commit/bac1c2ae14690fb915ab120209026ec535d7006c)
- fix(xtea): Fix the panic issue in the stream encryption by [@gouguoyin](https://github.com/gouguoyin) in [94596c4](https://github.com/dromara/dongle/commit/94596c48217968c3ff8b41bb8aad634589b8eb3f)
- test(crypto): Update error type assertion by [@gouguoyin](https://github.com/gouguoyin) in [15014ea](https://github.com/dromara/dongle/commit/15014eafc27c53190732f927f1d1c5a92f7aaaa1)
- fix(aes): Remove unnecessary comments by [@gouguoyin](https://github.com/gouguoyin) in [37d2aeb](https://github.com/dromara/dongle/commit/37d2aeb0b60ecaefb678d47c6204b796c5c86667)
- fix(crypto): Update 3DES decryption error type assertion by [@gouguoyin](https://github.com/gouguoyin) in [1d6ff35](https://github.com/dromara/dongle/commit/1d6ff357a03937d243cd7683dcc13c734b9e1673)
- feat(crypto): Add empty source data check by [@gouguoyin](https://github.com/gouguoyin) in [ba919b3](https://github.com/dromara/dongle/commit/ba919b3b4b1a72a6b2897f257de93c1257f124f7)
- feat(crypto): Add EmptySrcError type by [@gouguoyin](https://github.com/gouguoyin) in [3dd14a4](https://github.com/dromara/dongle/commit/3dd14a4347f0f9937121c83095c131477f0e6422)
- refactor(ed25519): Refactor key formatting method and adding compression method by [@gouguoyin](https://github.com/gouguoyin) in [5be56c1](https://github.com/dromara/dongle/commit/5be56c15213ce9f9f4866e96a39fa7b70003f5d5)
- refactor(rsa): Refactor RSA key formatting method and adding compression method by [@gouguoyin](https://github.com/gouguoyin) in [7fcd12c](https://github.com/dromara/dongle/commit/7fcd12c9ad6c1344a3f5b41a853ab15ad6f7c38b)
- feat(keypair): Add formatKeyBody function by [@gouguoyin](https://github.com/gouguoyin) in [0893b5d](https://github.com/dromara/dongle/commit/0893b5d553e5d39d7e02298b2cf9c74333157b21)
- refactor(ed25519): Remove non essential comments by [@gouguoyin](https://github.com/gouguoyin) in [734a5f2](https://github.com/dromara/dongle/commit/734a5f28b8de7e3c25e913204864ae2545f28c00)
- test(ed25519): Add edge testing for `StreamSigner.Write` method by [@gouguoyin](https://github.com/gouguoyin) in [db4dd67](https://github.com/dromara/dongle/commit/db4dd67489e99beaffd786a7372faf8204f8742d)
- refactor(crypto): Delete the Error field and instead handle errors through return values by [@gouguoyin](https://github.com/gouguoyin) in [b5d9349](https://github.com/dromara/dongle/commit/b5d9349626c42166b4a7449776267d79a116e25b)
- refactor(rsa): Change the return value of the `GenKeyPair` method from `*RsaKeyPair` to error by [@gouguoyin](https://github.com/gouguoyin) in [e384f4f](https://github.com/dromara/dongle/commit/e384f4f4104b471fe66e5c562f4d09c9934c31fc)
- chore(crypto): Simplify code by [@gouguoyin](https://github.com/gouguoyin) in [40e077a](https://github.com/dromara/dongle/commit/40e077a70621d70a24ea7ae948517ee280ffbcc0)
- chore(ed25519): Improve key generation and parsing error handling by [@gouguoyin](https://github.com/gouguoyin) in [20893dc](https://github.com/dromara/dongle/commit/20893dc7699413441b016f9f6d894e49a04d04b5)
- chore(rsa): Improve key generation and parsing error handling by [@gouguoyin](https://github.com/gouguoyin) in [ab5e7a8](https://github.com/dromara/dongle/commit/ab5e7a8643abceaa0d8db424f077c62ee0812705)

:::

## [v1.1.7](https://github.com/dromara/dongle/compare/v1.1.6...v1.1.7) (2025-10-20)

### ✨ 新機能

- `sm4` 中国国家標準ブロック暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含み、異なるブロックモードとパディングモードをサポート）

### 🐛 修正

- 非対称デジタル署名アルゴリズムの検証エラーのバグを修正 [#30](https://github.com/dromara/dongle/issues)
- ストリーム処理ロジックを最適化し、`reader` 位置リセットサポートを追加してデータソースの先頭から読み取りを保証し、以前の読み取り操作による位置オフセット問題を回避し、ストリーム操作の完全性と正確性を保証

### 🔧 リファクタリング

- `crypto/cipher/block.go` の `newXXXEncrypter` と `newXXXDecrypter` シリーズのプライベートメソッドを公開メソッド `NewXXXEncrypter` と `NewXXXDecrypter` に変更
- `crypto/cipher/padding.go` の `newXXXPadding` と `newXXXUnPadding` シリーズのプライベートメソッドを公開メソッド `NewXXXPadding` と `NewXXXUnPadding` に変更

::: details What's Changed (38)

- chore: Add support for the `io.Seeker` interface to reset the reading position by [@gouguoyin](https://github.com/gouguoyin) in [07a19a9](https://github.com/dromara/dongle/commit/07a19a9f8aa84467c990ba5f8bba127691d8d57e)
- refactor(decoder): ff -> f by [@gouguoyin](https://github.com/gouguoyin) in [ae38f87](https://github.com/dromara/dongle/commit/ae38f8726d927d89b0e15a403615f45bf594ee8d)
- refactor(test): Unify package import order by [@gouguoyin](https://github.com/gouguoyin) in [36064e0](https://github.com/dromara/dongle/commit/36064e00e84f241be486443ce662ef4282fb39be)
- docs(github/crypto): Add a period to the note on the encryption method by [@gouguoyin](https://github.com/gouguoyin) in [c4af6bd](https://github.com/dromara/dongle/commit/c4af6bda6fb61eb4077986bb063b06487e7b16dd)
- feat(crypto): Add support for the SM4 block cipher algorithm by [@gouguoyin](https://github.com/gouguoyin) in [537b615](https://github.com/dromara/dongle/commit/537b61571b316da39ecf35825fe9b836d2ebf2fb)
- chore(crypto/cipher): Remove the comment regarding the default number of rounds in TEA encryption by [@gouguoyin](https://github.com/gouguoyin) in [8b72470](https://github.com/dromara/dongle/commit/8b72470ddcfd09d5f4bf60af263e04a50b070826)
- feat(cipher): Unify function naming convention, newXXX -> NewXXX by [@gouguoyin](https://github.com/gouguoyin) in [cff507c](https://github.com/dromara/dongle/commit/cff507c1c017fb51b32ad36ee6b19f5e0a5904ef)
- build(dongle): Update the version number to v1.1.7 by [@gouguoyin](https://github.com/gouguoyin) in [22f0f85](https://github.com/dromara/dongle/commit/22f0f85edff9e1adf4b6f89d54bb198745ed1a5c)
- docs(crypto/cipher): Update the annotation of the padding function by [@gouguoyin](https://github.com/gouguoyin) in [f90f6a7](https://github.com/dromara/dongle/commit/f90f6a72f03094b72406e3b5cd137d48d157389a)
- chore(crypto/cipher): Unify error return variable names and remove redundant comments by [@gouguoyin](https://github.com/gouguoyin) in [6e9db0f](https://github.com/dromara/dongle/commit/6e9db0f539204120c1171c18910c16c7bd840612)
- fix(coding): Optimize the return value when there is an error by [@gouguoyin](https://github.com/gouguoyin) in [b581d3b](https://github.com/dromara/dongle/commit/b581d3b0e0bcc730862a67b0e5df23bf4931fa90)
- chore(crypto): Add initialization error checking by [@gouguoyin](https://github.com/gouguoyin) in [01d6ec7](https://github.com/dromara/dongle/commit/01d6ec7fb9d63076b0972be41d13e3c8ee21a4a2)
- test(aes): Delete unnecessary test cases by [@gouguoyin](https://github.com/gouguoyin) in [af904d0](https://github.com/dromara/dongle/commit/af904d0beaef51d3bf517d7e2fdf16768d068f10)
- test(des): Delete unnecessary test cases by [@gouguoyin](https://github.com/gouguoyin) in [b3f67f6](https://github.com/dromara/dongle/commit/b3f67f6119ff93591e35e8c22e18880baf9aa2cf)
- test(xtea): Delete unnecessary test cases by [@gouguoyin](https://github.com/gouguoyin) in [ba26567](https://github.com/dromara/dongle/commit/ba265670759eefde3289b66a4cd9812576b9b114)
- fix(cipher): Remove duplicate nil block checking logic by [@gouguoyin](https://github.com/gouguoyin) in [f13aa33](https://github.com/dromara/dongle/commit/f13aa3379956a74f71f5d9b88ab2da24ecd27a5c)
- chore(crypto/cipher):  Add CBC/ECB mode padding processing comments by [@gouguoyin](https://github.com/gouguoyin) in [1205cab](https://github.com/dromara/dongle/commit/1205cabfbc3a9ed1f0e02dd958b534c955c1d419)
- chore(crypto/cipher): Remove the early return logic when the extra data is empty by [@gouguoyin](https://github.com/gouguoyin) in [b66ba65](https://github.com/dromara/dongle/commit/b66ba65c00b70e9ffeb8079ad4c73298d2b5e66f)
- test(cipher): Remove duplicate decryption test cases by [@gouguoyin](https://github.com/gouguoyin) in [b534394](https://github.com/dromara/dongle/commit/b53439428b8250bee8ad6be99abfa50c7b6a526f)
- test(crypto): Remove test case for invalid cipher by [@gouguoyin](https://github.com/gouguoyin) in [d5b5849](https://github.com/dromara/dongle/commit/d5b5849e47ae3fcfcbf6bdee534bfb5f69a5d786)
- chore(coding): Add comments to Encoder and Decoder structures by [@gouguoyin](https://github.com/gouguoyin) in [57ae7a4](https://github.com/dromara/dongle/commit/57ae7a49b10dfd97cf59423df8ba588ab0bc216e)
- refactor(crypto): `UnsupportedModeError` -> `UnsupportedBlockModeError` by [@gouguoyin](https://github.com/gouguoyin) in [b6e71b1](https://github.com/dromara/dongle/commit/b6e71b1aee6144610666c754152d34d8ea9e38f2)
- docs(hash): Update package comments by [@gouguoyin](https://github.com/gouguoyin) in [3eb6ce7](https://github.com/dromara/dongle/commit/3eb6ce78ab14c36ea1975c88de24403da8fc5ec1)
- docs(cipher): Add comments by [@gouguoyin](https://github.com/gouguoyin) in [4ec008c](https://github.com/dromara/dongle/commit/4ec008cd28985af45e1d4e662a84a0610d102bb6)
- refactor(cipher): Remove unnecessary return parameters by [@gouguoyin](https://github.com/gouguoyin) in [4e52d83](https://github.com/dromara/dongle/commit/4e52d836fd958add802986472d00555d7a3d9d9a)
- fix(cipher): Improve encryption and decryption error handling logic by [@gouguoyin](https://github.com/gouguoyin) in [0d5947a](https://github.com/dromara/dongle/commit/0d5947adde7e5527451eded9d0348e15bb2161c4)
- feat(crypto): Add UnsupportedBlockModeError and UnsupportedPaddingModeError by [@gouguoyin](https://github.com/gouguoyin) in [2cc0511](https://github.com/dromara/dongle/commit/2cc05110fc959e80ea4ec38db0d42583bbc9d5ed)
- feat(cipher): Optimize zero padding logic by [@gouguoyin](https://github.com/gouguoyin) in [cbb4c56](https://github.com/dromara/dongle/commit/cbb4c56bba1ced5531f9f5db0da3625ab9219024)
- docs(keypair): Add comments by [@gouguoyin](https://github.com/gouguoyin) in [2122e07](https://github.com/dromara/dongle/commit/2122e078cd5a2809f99467ab63b2f19c18cf8512)
- docs: Update the description of padding mode and hash algorithms in the README by [@gouguoyin](https://github.com/gouguoyin) in [3d0dbb7](https://github.com/dromara/dongle/commit/3d0dbb7331bf3cfe9a24b5d724d9625d07c3967c)
- refactor(cipher): Refactor the padding and unpadding methods as receiver methods by [@gouguoyin](https://github.com/gouguoyin) in [3d73c89](https://github.com/dromara/dongle/commit/3d73c893c02790420ff478c289d07bde9b2b431b)
- chore(hash): Add comments by [@gouguoyin](https://github.com/gouguoyin) in [fe9ba67](https://github.com/dromara/dongle/commit/fe9ba67fab0fc15f79b0828d951597696019c6d4)
- chore(cipher): Unified error return format by [@gouguoyin](https://github.com/gouguoyin) in [063b25c](https://github.com/dromara/dongle/commit/063b25cdaf0f54255a330c60ad26f4c8c78db682)
- fix(rsa): Fix variable reference errors in signature verification logic, `kp.Sign` -> `v.sign` by [@gouguoyin](https://github.com/gouguoyin) in [e78cd47](https://github.com/dromara/dongle/commit/e78cd4790c21631c9c6b98b085e903b0ca645927)
- test: Add issue #30 unit test cases by [@gouguoyin](https://github.com/gouguoyin) in [2cb142a](https://github.com/dromara/dongle/commit/2cb142a0a254492ab3d2659977a41817c5194505)
- feat(crypto): Add verify status field to enhance signature verification logic by [@gouguoyin](https://github.com/gouguoyin) in [c7a76bd](https://github.com/dromara/dongle/commit/c7a76bde0309f0ede7c0a2817cfebf25e57a180e)
- refactor(utils): []byte("") -> []byte{} by [@gouguoyin](https://github.com/gouguoyin) in [7e378cd](https://github.com/dromara/dongle/commit/7e378cdaf2e0a3beae291a6c7a4e22649ccb66e8)
- vm-os: [ubuntu-latest, macos-latest, windows-latest] by kuafuRace in [340283c](https://github.com/dromara/dongle/commit/340283c3bc40c815a1a3a200121fb3ec85717e56)

:::

## [v1.1.6](https://github.com/dromara/dongle/compare/v1.1.5...v1.1.6) (2025-10-12)

### ✨ 新機能

- `tea` 暗号化アルゴリズムを最適化し、異なるブロックモードとパディングモードをサポート
- `xtea` 暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

### 🔧 リファクタリング

- `io.CopyBuffer` を使用してストリーム処理ロジックを簡素化

::: details What's Changed (26)

- docs(readme): Update the import path in README.cn.md by [@gouguoyin](https://github.com/gouguoyin) in [dbe8da4](https://github.com/dromara/dongle/commit/dbe8da409fec120d96d78e70db2fac28c99e2540)
- refactor: Rename the `util` package to `utils` by [@gouguoyin](https://github.com/gouguoyin) in [9c4122e](https://github.com/dromara/dongle/commit/9c4122e91d056685d0d20e3ac01599b9911c2079)
- refactor(cipher): decrypted -> paddedDst by [@gouguoyin](https://github.com/gouguoyin) in [4537c96](https://github.com/dromara/dongle/commit/4537c9668f26c743f975df9c57e3a602edfac059)
- refactor(mock): Unify the naming of receivers in error file simulation by [@gouguoyin](https://github.com/gouguoyin) in [def9c0a](https://github.com/dromara/dongle/commit/def9c0a2d397029af94fb3fd67d883769f4f26b4)
- refactor(mock): Move package comment from `file.go` to `doc.go` by [@gouguoyin](https://github.com/gouguoyin) in [0a86b4a](https://github.com/dromara/dongle/commit/0a86b4ae590ea394a619a15cae8a617d0e1f41a7)
- refactor(utils): Add package comment in `doc.go` by [@gouguoyin](https://github.com/gouguoyin) in [d625676](https://github.com/dromara/dongle/commit/d6256768e372f5d2eb4031314c3ae381d8f43292)
- style: Add necessary notes by [@gouguoyin](https://github.com/gouguoyin) in [35ed473](https://github.com/dromara/dongle/commit/35ed4730d22efb132191673aac8a0bd98c9e2cb7)
- docs: Add package comments by [@gouguoyin](https://github.com/gouguoyin) in [08ddc95](https://github.com/dromara/dongle/commit/08ddc95b01df0e70df5bbd02507de075debb8579)
- chore(encoder):Optimize error handling logic by [@gouguoyin](https://github.com/gouguoyin) in [6b723b5](https://github.com/dromara/dongle/commit/6b723b5cfa7b1f137cf359adff05976ecd4cb7dd)
- chore(coding): Unify the naming of error handling variables and optimize the reading logic by [@gouguoyin](https://github.com/gouguoyin) in [3d16e0f](https://github.com/dromara/dongle/commit/3d16e0fe9278a36f48957f035790172d81610d31)
- chore(crypto): Unify the naming of error handling variables and optimize the reading logic by [@gouguoyin](https://github.com/gouguoyin) in [ca35d52](https://github.com/dromara/dongle/commit/ca35d527c9e9bc5a8cbb6c4d9ef989aecfa77a49)
- test: Add test case for issue #28 by [@gouguoyin](https://github.com/gouguoyin) in [b87981c](https://github.com/dromara/dongle/commit/b87981c45ce0af27224be29a1f4bc28e193cba27)
- build: Update version number to `1.1.6` by [@gouguoyin](https://github.com/gouguoyin) in [4a16814](https://github.com/dromara/dongle/commit/4a168143d9f1eb636cc7aa31791667d83246b937)
- refactor(hash): Use `io.CopyBuffer` to replace manual reading of the buffer, simplifying the implementation of `stream` and `hmac` methods by [@gouguoyin](https://github.com/gouguoyin) in [cf399b5](https://github.com/dromara/dongle/commit/cf399b522231f14c0a5515bab4d06665eb7e6acf)
- fix(blowfish): Fix the return value counting logic after encrypted data is written by [@gouguoyin](https://github.com/gouguoyin) in [70ea1f7](https://github.com/dromara/dongle/commit/70ea1f7e7c39750640a0c74d7cf4c0111635a2bd)
- refactor(ed25519): Remove redundant random number generator by [@gouguoyin](https://github.com/gouguoyin) in [6c974f4](https://github.com/dromara/dongle/commit/6c974f481df9a27a6cd004285fb5c38a2c49119c)
- fix(rsa): Optimize RSA key parsing logic and fix return value handling by [@gouguoyin](https://github.com/gouguoyin) in [6ca625c](https://github.com/dromara/dongle/commit/6ca625c8597cfed7394dcc098f9408ea8feaeaed)
- feat(crypto): Use `io.CopyBuffer` to improve the performance and efficiency of stream processing readability and fixing potential read error issues by [@gouguoyin](https://github.com/gouguoyin) in [b1d4247](https://github.com/dromara/dongle/commit/b1d42476ecb8738ed71ce7f528bc635f6c59da26)
- refactor(decoder):Simplify streaming process with `io.CopyBuffer` by [@gouguoyin](https://github.com/gouguoyin) in [bc1c6ab](https://github.com/dromara/dongle/commit/bc1c6aba56612363682937b2d2e3a0afe44c4438)
- refactor(encoder):Simplify streaming process with `io.CopyBuffer` by [@gouguoyin](https://github.com/gouguoyin) in [730c151](https://github.com/dromara/dongle/commit/730c151ed06cbed7b14359c16843e17b9b1a115e)
- feat(crypto/tea): Optimize the tea algorithm to support different blocking and padding modes by [@gouguoyin](https://github.com/gouguoyin) in [817e4c5](https://github.com/dromara/dongle/commit/817e4c5f872fa8570c934b056b5411090a13e675)
- feat(crypto/xtea): Add support for `xtea` algorithm by [@gouguoyin](https://github.com/gouguoyin) in [6cc0c01](https://github.com/dromara/dongle/commit/6cc0c01c58412a86b8cecf25859cd62f503c2512)
- test(3des): Remove useless and erroneous tests by [@gouguoyin](https://github.com/gouguoyin) in [2df56d8](https://github.com/dromara/dongle/commit/2df56d8e3f0d9b765d9f84930e7e1b43f2d5cbe1)
- test: Replace the existing custom errorCloser with CloseErrorWriteCloser from the mock library by [@gouguoyin](https://github.com/gouguoyin) in [e70157b](https://github.com/dromara/dongle/commit/e70157bb2d919547db55d157926b00f7d30c4e56)
- feat(cipher): Update the implementation of the TEA encryption algorithm to support block mode by [@gouguoyin](https://github.com/gouguoyin) in [b90d008](https://github.com/dromara/dongle/commit/b90d00812c3dd8ed8ab9d8722b891dcd4d334587)
- style: Unify the function annotation style and revise some algorithm descriptions by [@gouguoyin](https://github.com/gouguoyin) in [9509d43](https://github.com/dromara/dongle/commit/9509d43faacdc2d04c029975e6476f62e7dc3118)

:::

## [v1.1.5](https://github.com/dromara/dongle/compare/v1.1.4...v1.1.5) (2025-10-01)

### 🐛 修正

- パディングが不要なブロックモード（CFB/OFB/CTR/GCM など）で対称暗号化アルゴリズムがパディングを実行した際の暗号化/復号化エラーのバグを修正

::: details What's Changed (6)

- build(dongle): Updated version number to 1.1.5 by [@gouguoyin](https://github.com/gouguoyin) in [8e1a462](https://github.com/dromara/dongle/commit/8e1a462ddc3795a92bb7f30b2333df666cb30dd0)
- test(issue): Add issue test file by [@gouguoyin](https://github.com/gouguoyin) in [d77ad8c](https://github.com/dromara/dongle/commit/d77ad8c640a464f329edc47fa11d60f2dc04024e)
- refactor(crypto): Unify package grouping import rule by [@gouguoyin](https://github.com/gouguoyin) in [17ff89c](https://github.com/dromara/dongle/commit/17ff89cc59e615b7299d262a6ebf55497c03e152)
- test(aes): Remove t.Skip test cases by [@gouguoyin](https://github.com/gouguoyin) in [82f450f](https://github.com/dromara/dongle/commit/82f450f501a3082bdf8b97c53b2a056fbf6b2002)
- refactor(coding): Unify package grouping import rule by [@gouguoyin](https://github.com/gouguoyin) in [833c1c2](https://github.com/dromara/dongle/commit/833c1c29fd2f1f09f553acd9f035df20fb2e4c4c)
- refactor(cipher): Optimize the logical structure of encryption and decryption #29 by [@gouguoyin](https://github.com/gouguoyin) in [a598772](https://github.com/dromara/dongle/commit/a5987721f7047ba3f9c57ca493439df95e7a5ff1)

:::

## [v1.1.4](https://github.com/dromara/dongle/compare/v1.1.3...v1.1.4) (2025-09-23)

### ✨ 新機能

- `twofish` 暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

### 🔧 リファクタリング

- グローバルデフォルトインスタンス使用時のプロパティ汚染を防ぐため、メソッドレシーバーをポインタから値に変更、呼び出し側 `API` への影響はなし

::: details What's Changed (5)

- build(dongle.go): Update the version number to v1.1.4 by [@gouguoyin](https://github.com/gouguoyin) in [3abadc6](https://github.com/dromara/dongle/commit/3abadc6238b6d9bf5515f4fb3544fd47ef9de424)
- refactor: Change the receiver of the method from a pointer type to a value type by [@gouguoyin](https://github.com/gouguoyin) in [9b9b104](https://github.com/dromara/dongle/commit/9b9b104322a77b45d868cb9bff5970d86ab26a7d)
- docs(chacha20): Add package comments``` by [@gouguoyin](https://github.com/gouguoyin) in [3a66727](https://github.com/dromara/dongle/commit/3a6672794a38634f60bf09a0bc664d10a10c13e3)
- docs(chacha20poly1305): Add package comments by [@gouguoyin](https://github.com/gouguoyin) in [25b9c56](https://github.com/dromara/dongle/commit/25b9c560eced9b33f0fcedd1bd3f8445fcfc341b)
- feat(crypto): Add support for the Twofish encryption algorithm by [@gouguoyin](https://github.com/gouguoyin) in [fd78849](https://github.com/dromara/dongle/commit/fd788494e217bc9fe9f354bb9c37e64ada700716)

:::

## [v1.1.3](https://github.com/dromara/dongle/compare/v1.1.2...v1.1.3) (2025-09-15)

### ✨ 新機能

- `testify` 依存関係を `v1.11.1` に更新

### 🐛 修正

- `3DES` 対称暗号化アルゴリズムの `16` バイトキー互換性を最適化
- `DES` 対称暗号化アルゴリズムのサポートされていない `GCM` モード検証を最適化
- `3DES` 対称暗号化アルゴリズムのサポートされていない `GCM` モード検証を最適化
- `Blowfish` 対称暗号化アルゴリズムのサポートされていない `GCM` モード検証を最適化

### 🔧 リファクタリング

- `Salsa20` 暗号化アルゴリズムサポートを追加（標準処理とストリーム処理を含む）

::: details What's Changed (21)

- chore(deps): Update the testify dependency to `v1.11.1` by [@gouguoyin](https://github.com/gouguoyin) in [6644d40](https://github.com/dromara/dongle/commit/6644d40e5f6f6a1739566e3b797f954546a4f66f)
- chore: Update dongle to `v1.1.3` by [@gouguoyin](https://github.com/gouguoyin) in [efa7ffd](https://github.com/dromara/dongle/commit/efa7ffd21a112307998049238f48c190a8f0e6e0)
- perf(hash/md2): []byte{} -> var data []byte by [@gouguoyin](https://github.com/gouguoyin) in [e4c4362](https://github.com/dromara/dongle/commit/e4c43624fd27ab4d0414d3a27a79eb5ee0b87fdd)
- refactor(hash): Unify import package order by [@gouguoyin](https://github.com/gouguoyin) in [57a68fa](https://github.com/dromara/dongle/commit/57a68faaa3ceabe978bddf07e0f0e2f4b53edffb)
- perf(test): []byte{} -> var data []byte by [@gouguoyin](https://github.com/gouguoyin) in [f2c7321](https://github.com/dromara/dongle/commit/f2c73217f418e324472a46471a3e8ef5d0a03fda)
- feat(crypto): Add support for the Salsa20 encryption algorithm by [@gouguoyin](https://github.com/gouguoyin) in [8df1550](https://github.com/dromara/dongle/commit/8df155026c026228fc1bcbc2682db44f1c2123c3)
- fix(crypto/des): Add a error check for unsupported `GCM` mode by [@gouguoyin](https://github.com/gouguoyin) in [10c123d](https://github.com/dromara/dongle/commit/10c123dbe37ab29287124566722fa9a8f7202138)
- fix(crypto/blowfish): Add an error check for unsupported `GCM` mode by [@gouguoyin](https://github.com/gouguoyin) in [7f343cb](https://github.com/dromara/dongle/commit/7f343cb0aadbcf39a8e78336a61e0629d69ec5a0)
- fix(crypto/3des): Add an error check for unsupported `GCM` mode by [@gouguoyin](https://github.com/gouguoyin) in [6c12f0c](https://github.com/dromara/dongle/commit/6c12f0c1932edb2469f37197559a56ce7df1ba57)
- fix(crypto/des): Add an error check for unsupported `GCM` mode by [@gouguoyin](https://github.com/gouguoyin) in [895547e](https://github.com/dromara/dongle/commit/895547e6ddfe891151084ca31105915f133a6905)
- refactor(crypto/aes): Optimize AES encryption and decryption operations by [@gouguoyin](https://github.com/gouguoyin) in [436ae5e](https://github.com/dromara/dongle/commit/436ae5e45c4c3f738d4eb7dfb7d8b8c122926a74)
- test(3des): Create alone test files for each block cipher mode by [@gouguoyin](https://github.com/gouguoyin) in [ae47981](https://github.com/dromara/dongle/commit/ae4798171b33b7d17c2de485fb1b5ba919f4ab26)
- test(aes): Create alone test files for each block cipher mode by [@gouguoyin](https://github.com/gouguoyin) in [4c1c349](https://github.com/dromara/dongle/commit/4c1c3491c18fc20db73cd41c42fc27ec25be4fcf)
- test(blowfish): Create alone test files for each block cipher mode by [@gouguoyin](https://github.com/gouguoyin) in [31cfeab](https://github.com/dromara/dongle/commit/31cfeabb4c84b7bf7e73f325082b47bd65b69c29)
- test(des): Create alone test files for each block cipher mode by [@gouguoyin](https://github.com/gouguoyin) in [171eb70](https://github.com/dromara/dongle/commit/171eb70a25852689fb0c39bc4529008f1619b0af)
- fix(crypto/chacha20): Unify import package order by [@gouguoyin](https://github.com/gouguoyin) in [d8c9242](https://github.com/dromara/dongle/commit/d8c9242e5bf84eeeb42381035db605b1b1ba524f)
- chore(crypto/chacha20loly1305): Unify import package order by [@gouguoyin](https://github.com/gouguoyin) in [718779f](https://github.com/dromara/dongle/commit/718779fc7a3852bdf8f15d5c6f3e09a7e752df4c)
- test(rc4): Modify the test case description by [@gouguoyin](https://github.com/gouguoyin) in [f3cad2b](https://github.com/dromara/dongle/commit/f3cad2be85605404e135740d5e157386c1091c7e)
- test(crypto): Unify import package order by [@gouguoyin](https://github.com/gouguoyin) in [8a8361a](https://github.com/dromara/dongle/commit/8a8361a3c2b8905cf23615c65e5bb9ee98d27c9c)
- perf(benchmarks): init -> initBenchData by [@gouguoyin](https://github.com/gouguoyin) in [88e5a2f](https://github.com/dromara/dongle/commit/88e5a2f0e1eb46e832b319ac081a2d8dc03cc208)
- feat(crypto): Add documentation comments for the package by [@gouguoyin](https://github.com/gouguoyin) in [9fbddeb](https://github.com/dromara/dongle/commit/9fbddeba262aa561177d8698e044ace75b0094ff)

:::

## [v1.1.2](https://github.com/dromara/dongle/compare/v1.1.1...v1.1.2) (2025-09-08)

### ✨ 新機能

- エンコード/デコードが `coding.BufferSize` グローバル変数によるファイルストリームバッファサイズのカスタマイズをサポート
- 暗号化/復号化が `crypto.BufferSize` グローバル変数によるファイルストリームバッファサイズのカスタマイズをサポート
- Hash/Hmacアルゴリズムが `hash.BufferSize` グローバル変数によるファイルストリームバッファサイズのカスタマイズをサポート
- `Blake2b` ハッシュアルゴリズムサポートを追加（`blake2b-256`、`blake2b-384`、`blake2b-512` を含む）
- `Blake2s` ハッシュアルゴリズムサポートを追加（`blake2s-128`、`blake2s-256` を含む）
- `ChaCha20` 暗号化アルゴリズムサポートを追加
- `ChaCha20Poly1305` 暗号化アルゴリズムサポートを追加

::: details What's Changed (24)

- fix(crypto): Remove redundant code by [@gouguoyin](https://github.com/gouguoyin) in [05ec861](https://github.com/dromara/dongle/commit/05ec861659a9ba386cb21a0b206180bc54f83e12)
- feat(crypto): Add support for the `ChaCha20` encryption algorithm by [@gouguoyin](https://github.com/gouguoyin) in [cdff998](https://github.com/dromara/dongle/commit/cdff9983daa062306cc7fe5c341d26f59bcca0aa)
- docs: Update usage examples by [@gouguoyin](https://github.com/gouguoyin) in [6710e8f](https://github.com/dromara/dongle/commit/6710e8fe50a28649ff1eed7a037f05ee7e9abbe2)
- refactor(coding): Add BufferSize global variable to define the buffer size for stream processing by [@gouguoyin](https://github.com/gouguoyin) in [2fecf80](https://github.com/dromara/dongle/commit/2fecf804f364dfc367a4dc4db66b14da8ad9cbb5)
- refactor(hash): Add BufferSize global variable to define the buffer size for stream processing by [@gouguoyin](https://github.com/gouguoyin) in [870c557](https://github.com/dromara/dongle/commit/870c5571cc6877c65fe444bbb62546fcc7a74716)
- refactor(crypto): Add BufferSize global variable to define the buffer size for stream processing by [@gouguoyin](https://github.com/gouguoyin) in [768d89d](https://github.com/dromara/dongle/commit/768d89db4da8f1a5b69e99a45e73fc1e7ffe84af)
- refactor(hash): hash -> hashFunc by [@gouguoyin](https://github.com/gouguoyin) in [f68a56c](https://github.com/dromara/dongle/commit/f68a56cde898d15bb9624c8f5c8c55bfb61126eb)
- refactor(hash): Optimize error messages by [@gouguoyin](https://github.com/gouguoyin) in [1d4d33b](https://github.com/dromara/dongle/commit/1d4d33b31f292b277a50cff38792d98030c94d9c)
- docs(README): Add digital signature and verification example by [@gouguoyin](https://github.com/gouguoyin) in [762ba1c](https://github.com/dromara/dongle/commit/762ba1ce006ad557d1f63b9c66bda42c25a9c0b2)
- docs: Remove the digital signature and verification example by [@gouguoyin](https://github.com/gouguoyin) in [2eeccf2](https://github.com/dromara/dongle/commit/2eeccf267eb08709dd483860d1cc63782a14a6aa)
- docs(README): Update RSA signature verification example by [@gouguoyin](https://github.com/gouguoyin) in [49e802b](https://github.com/dromara/dongle/commit/49e802bce3d929c418beb563c0b95aa6ea0df220)
- refactor(hash): Remove the redundant variable totalBytes by [@gouguoyin](https://github.com/gouguoyin) in [e14030d](https://github.com/dromara/dongle/commit/e14030d7c9def1ef8d4d05e5507dbab18484d163)
- feat(hash): Add support for the `BLAKE2b` hash algorithm by [@gouguoyin](https://github.com/gouguoyin) in [0683cc0](https://github.com/dromara/dongle/commit/0683cc0116199704963e7215c518b95351697c70)
- feat(hash): Add support for the `BLAKE2s` hash algorithm by [@gouguoyin](https://github.com/gouguoyin) in [f5870d7](https://github.com/dromara/dongle/commit/f5870d74b6cd4ed590406097e60e77c4ed536c3c)
- test(hash): Unified import of grouping styles by [@gouguoyin](https://github.com/gouguoyin) in [74c2c4a](https://github.com/dromara/dongle/commit/74c2c4a5023d4b6e9450ee853fb67b1075ea41f6)
- test(coding): Unified import of grouping styles by [@gouguoyin](https://github.com/gouguoyin) in [6bb8efd](https://github.com/dromara/dongle/commit/6bb8efd53bfc7a5b34742892268a91ed8d6a6969)
- test(crypto): Unified import of grouping styles by [@gouguoyin](https://github.com/gouguoyin) in [63e3e81](https://github.com/dromara/dongle/commit/63e3e81db792fb0d2f31976d4ae18bdb06d43bbd)
- test(keypair): Unified import of grouping styles by [@gouguoyin](https://github.com/gouguoyin) in [72be367](https://github.com/dromara/dongle/commit/72be367c9eb5efd8583fe4c36c992e96b83936a2)
- test(cipher): Unified import of grouping styles by [@gouguoyin](https://github.com/gouguoyin) in [6961d3f](https://github.com/dromara/dongle/commit/6961d3ff04f2de09404107eaca72a9f01e156758)
- test(cipher): blockCipher.Aad -> blockCipher.AAD by [@gouguoyin](https://github.com/gouguoyin) in [04848cc](https://github.com/dromara/dongle/commit/04848cc3c0d6c095ee65e4d2661ba6c651421e10)
- feat(crypto): Add support for `ChaCha20-Poly1305` encryption algorithm by [@gouguoyin](https://github.com/gouguoyin) in [8e3b5c3](https://github.com/dromara/dongle/commit/8e3b5c31b229ffabb17a30f6c1655d24dd7b28bd)
- docs(README): `hex string` -> `hex-encoded string`, `base64 string` -> `base64-encoded string` by [@gouguoyin](https://github.com/gouguoyin) in [2c78e49](https://github.com/dromara/dongle/commit/2c78e4938189c8f40620c583543df7b9c6067d27)
- docs(README): Use the import block to uniformly import multiple packages by [@gouguoyin](https://github.com/gouguoyin) in [7d8e358](https://github.com/dromara/dongle/commit/7d8e358241466250e6357ad02d610a3b071c32fc)
- build: Update the version number to 1.1.2 by [@gouguoyin](https://github.com/gouguoyin) in [80b23e0](https://github.com/dromara/dongle/commit/80b23e0bb17cb070ba24ce33f918c3e90f543162)

:::

## [v1.1.1](https://github.com/dromara/dongle/compare/v1.1.0...v1.1.1) (2025-09-01)

### ✨ 新機能

- エンコード/デコード、暗号化/復号化、Hash/Hmac、署名/検証の真のストリーム処理をサポート
- `ED25519` デジタル署名と検証サポートを追加
- `SM3` ハッシュアルゴリズムサポートを追加
- `coding/morse/morse.go` にスペース、句読点、特殊文字のサポートを追加

### ⚡ パフォーマンス

- 入力データが空の場合、後続処理を実行せずに直接空データを返す

### 🔧 リファクタリング

- 対称暗号化アルゴリズムを `ByXXX(cipher.XXXCipher)` から `ByXXX(*cipher.XXXCipher)` に変更
- ユーティリティパッケージ名を `utils` から `util` に変更
- `hash.Hash` インターフェースのエラーをモックするための `mock/hash.go` を追加

::: details What's Changed (42)

- docs(readme): Update RSA encryption and decryption example by [@gouguoyin](https://github.com/gouguoyin) in [4094aac](https://github.com/dromara/dongle/commit/4094aacb95a6d741f8cca4dbb5f08c177e2f89ec)
- refactor: Rename utils package to util by [@gouguoyin](https://github.com/gouguoyin) in [9242991](https://github.com/dromara/dongle/commit/92429912b853f7845bf28094758e737d3c021448)
- feat(hash): Add support for `SM3` hash algorithm by [@gouguoyin](https://github.com/gouguoyin) in [3f6e407](https://github.com/dromara/dongle/commit/3f6e4076c4d4f50dcb25042d923fa9acecb2a2e9)
- refactor(crypto/3des): Refactor 3DES encryptor and decryptor by [@gouguoyin](https://github.com/gouguoyin) in [4ed070e](https://github.com/dromara/dongle/commit/4ed070ed9d313a454917de4db1ddee204022c2ea)
- refactor(crypto): Refactor AES encryptor and decryptor by [@gouguoyin](https://github.com/gouguoyin) in [6a3dcf9](https://github.com/dromara/dongle/commit/6a3dcf995d48541ef7fb5bcdfa48656b9361a52f)
- refactor(crypto): Refactor DES encryptor and decryptor by [@gouguoyin](https://github.com/gouguoyin) in [39193c7](https://github.com/dromara/dongle/commit/39193c75f828474e4dbd2438f9df5dbf95b299bf)
- refactor(rc4): Change the parameter type of the ByRc4 method from `cipher.Rc4Cipher` to `*cipher.Rc4Cipher` by [@gouguoyin](https://github.com/gouguoyin) in [4bcba4e](https://github.com/dromara/dongle/commit/4bcba4e352dd943faa827b13835b3659a287d5f4)
- refactor(tea): `cipher.TeaCipher` -> `*cipher.TeaCipher` by [@gouguoyin](https://github.com/gouguoyin) in [f90f82c](https://github.com/dromara/dongle/commit/f90f82cb6a4bdae7c544c3f65bf7f767f1b8e032)
- refactor(tea): `cipher.BlowfishCipher` -> `*cipher.BlowfishCipher` by [@gouguoyin](https://github.com/gouguoyin) in [af4db9d](https://github.com/dromara/dongle/commit/af4db9d4d37cc119d9cfd804668aa3868a7edb25)
- refactor(crypto/cipher):Rename the `padding` function and remove the internal `dispatcher` by [@gouguoyin](https://github.com/gouguoyin) in [e44f321](https://github.com/dromara/dongle/commit/e44f321e35c2e3ab70a1816fab59a42a2ffb3aeb)
- feat(crypto): Add the blockCipher struct and encryption/decryption functionality by [@gouguoyin](https://github.com/gouguoyin) in [0c93355](https://github.com/dromara/dongle/commit/0c933558ab15c93d13bbe96a67d57017bd50e295)
- refactor(crypto/cipher): Change the encryptor and decryptor methods to private by [@gouguoyin](https://github.com/gouguoyin) in [4ab52bd](https://github.com/dromara/dongle/commit/4ab52bd8d51dc17a8ea5874ef4739ec833b06a89)
- refactor(cipher): Refactor the password encoder structure and optimize test cases by [@gouguoyin](https://github.com/gouguoyin) in [f904e13](https://github.com/dromara/dongle/commit/f904e13762fd440e7f77c40fbf716222cf088f09)
- refactor(mock):  data := []byte{} -> var data []byte by [@gouguoyin](https://github.com/gouguoyin) in [40178d8](https://github.com/dromara/dongle/commit/40178d80d9300fcf0e26fa8d659f37e7e7287a4a)
- refactor: Use `mock.NewFile` instead of `strings.NewReader` and `bytes.NewReader` by [@gouguoyin](https://github.com/gouguoyin) in [b77f6c3](https://github.com/dromara/dongle/commit/b77f6c38f2dfea60636e86b99106dfae698bbea6)
- refactor: Use the `errors.As` function instead of type assertion by [@gouguoyin](https://github.com/gouguoyin) in [c4ddfd0](https://github.com/dromara/dongle/commit/c4ddfd0db607550b218ec16a40a729f0977c2ea4)
- feat: Add `FromFile` method by [@gouguoyin](https://github.com/gouguoyin) in [a07314f](https://github.com/dromara/dongle/commit/a07314fbd15a0f0a5d2473203c4e859a9f919ec2)
- refactor: []byte{} -> var []byte by [@gouguoyin](https://github.com/gouguoyin) in [01ebf5e](https://github.com/dromara/dongle/commit/01ebf5e3ab46d2a58947695b11d2327c57efb9ba)
- test(crypto/cipher): Remove redundant comments by [@gouguoyin](https://github.com/gouguoyin) in [e0fb4d0](https://github.com/dromara/dongle/commit/e0fb4d066685336bea55da3d1215bf85a367f5ec)
- test: TestErrorTypes -> TestRsaErrorTypes by [@gouguoyin](https://github.com/gouguoyin) in [cd0a48a](https://github.com/dromara/dongle/commit/cd0a48a0e00072b9d6fa30a505107256b05e75a7)
- refactor(crypto): triple_des -> tripleDes by [@gouguoyin](https://github.com/gouguoyin) in [e3add07](https://github.com/dromara/dongle/commit/e3add07935ac5926a1d5c4cd62f5c73e8197ced0)
- feat(crypto): Add ED25519 signature and verification methods by [@gouguoyin](https://github.com/gouguoyin) in [39f0ce3](https://github.com/dromara/dongle/commit/39f0ce303dfd27e6cd10626ff03a22a3210ed82e)
- refactor(crypto): Update variable naming to use camelCase by [@gouguoyin](https://github.com/gouguoyin) in [50d5d4b](https://github.com/dromara/dongle/commit/50d5d4b6c1aaaae0a06271c3bb4ab000ad4391ef)
- perf(crypto): Remove the error checking for the result of `hasher.Write` by [@gouguoyin](https://github.com/gouguoyin) in [966bdd5](https://github.com/dromara/dongle/commit/966bdd52fb1b6bf9b010ab8109f79dd8ca7c5553)
- refactor(mock): Added `mock/hash.go` to simulate error conditions of the `hash.Hash` interface by [@gouguoyin](https://github.com/gouguoyin) in [4e38f79](https://github.com/dromara/dongle/commit/4e38f7943bc08c94ea3864e32d18e0331f5194a2)
- test(coding): Optimize code and add benchmark tests by [@gouguoyin](https://github.com/gouguoyin) in [ce64a33](https://github.com/dromara/dongle/commit/ce64a33547e4882da7ef6aea410d17a74b171a1c)
- test(hash): Optimize code and add benchmark tests by [@gouguoyin](https://github.com/gouguoyin) in [a30f570](https://github.com/dromara/dongle/commit/a30f570c5252159d589c8f659f0057294981b16f)
- feat: Implement true streaming encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [0fdc666](https://github.com/dromara/dongle/commit/0fdc6660464d02ea0b18ac4fdff148fde5f79d0b)
- feat: Implement true streaming hashing by [@gouguoyin](https://github.com/gouguoyin) in [916d8f3](https://github.com/dromara/dongle/commit/916d8f3d7cd421d4f3bc73794e99a356dfd52a8d)
- refactor(mock): Improve the Sum method of ErrorHasher and add test cases by [@gouguoyin](https://github.com/gouguoyin) in [913ef51](https://github.com/dromara/dongle/commit/913ef51c45ed55c0cac68314b093389b14576356)
- feat(crypto): Refactor the ED25519 stream signature and verification logic to achieve true stream signature and verification by [@gouguoyin](https://github.com/gouguoyin) in [704bdda](https://github.com/dromara/dongle/commit/704bdda55d2878d60b4f561e2af9cfd959feb83f)
- fix(crypto): Optimize the logic of Close and ReadAll by [@gouguoyin](https://github.com/gouguoyin) in [fa1e139](https://github.com/dromara/dongle/commit/fa1e139948edccdde6e2d1976aa4beb3e2a49324)
- refactor(crypto): Refactor the Encrypter.stream method to implement true streaming encryption by [@gouguoyin](https://github.com/gouguoyin) in [71ad312](https://github.com/dromara/dongle/commit/71ad3128811d45a2ae0a73b3ce52e442cd979852)
- test(rc4): Optimize the test coverage for RC4 by [@gouguoyin](https://github.com/gouguoyin) in [38b2928](https://github.com/dromara/dongle/commit/38b2928beb9e2648905395bf5b714c7b6631a9cc)
- feat: Implement true streaming encryption and decryption by [@gouguoyin](https://github.com/gouguoyin) in [961dc5d](https://github.com/dromara/dongle/commit/961dc5ded55f0767eecbbcb7d3a0128164bf0b23)
- build: Update the version number to 1.1.1 by [@gouguoyin](https://github.com/gouguoyin) in [a2c746b](https://github.com/dromara/dongle/commit/a2c746b1063b0a29ae37b7f5f372cb72beda2cfc)
- feat(morse): Add support for spaces, punctuation marks, and special characters by [@gouguoyin](https://github.com/gouguoyin) in [017497c](https://github.com/dromara/dongle/commit/017497c7a3a88757d13a26bc6e03febd5556f437)
- fix(crypto/3des): Return null data when encrypting or decrypting null data by [@gouguoyin](https://github.com/gouguoyin) in [3145828](https://github.com/dromara/dongle/commit/3145828f3de782aa3022a0367c34f392c7368e42)
- fix(crypto/aes): Return null data when encrypting or decrypting null data by [@gouguoyin](https://github.com/gouguoyin) in [f19243d](https://github.com/dromara/dongle/commit/f19243d3c55ee1e408bf417b87b72b6465a86d58)
- fix(crypto/blowfish): Return null data when encrypting or decrypting null data by [@gouguoyin](https://github.com/gouguoyin) in [e9c1905](https://github.com/dromara/dongle/commit/e9c19052eed42a005379c4f2e2172fa61f4d2fc6)
- fix(crypto/des): Return null data when encrypting or decrypting null data by [@gouguoyin](https://github.com/gouguoyin) in [7ad600f](https://github.com/dromara/dongle/commit/7ad600f63e91320131ce400b3e380f252859a701)
- test: Use `mock.NewFile` instead of `strings.NewReader` and `bytes.NewReader` by [@gouguoyin](https://github.com/gouguoyin) in [c70e218](https://github.com/dromara/dongle/commit/c70e218f66841f758ad1e98e593da1584317730e)

:::

## [v1.1.0](https://github.com/dromara/dongle/compare/v1.0.1...v1.1.0) (2025-08-23)

> ⚠️ これは破壊的な更新バージョンです。慎重にアップグレードしてください。ただし、アップグレードを強く推奨します

### ✨ 新機能

- `ファイルストリーム` のエンコード/デコード、暗号化/復号化、Hash/Hmac、署名/検証サポートを追加
- `ByBase32Hex` エンコード/デコードメソッドを新規追加
- `base32/base32Hex` エンコードにカスタム文字セットサポートを追加
- `base45` エンコードにカスタム文字セットサポートを追加
- `base58` エンコードにカスタム文字セットサポートを追加
- `base62` エンコードにカスタム文字セットサポートを追加
- `base64/base64Url` エンコードにカスタム文字セットサポートを追加

### 🔧 リファクタリング

- `BySafeURL` エンコード/デコードメソッドを削除
- `Sm3` ハッシュアルゴリズム(`hash`)とメッセージ認証コードアルゴリズム(`hmac`)を削除
- `ByBase64URL` エンコード/デコードメソッドを `ByBase64Url` に名前変更
- ハッシュアルゴリズム(`hash`)呼び出し方式を `dongle.Encrypt.ByXXX()` から `dongle.Hash.ByXXX()` に変更
- メッセージ認証コードアルゴリズム(`hmac`)呼び出し方式を `dongle.Encrypt.ByHmacXXX()` から `dongle.Hash.WithKey().ByXXX()` に変更
- `AES`, `DES`, `3DES`, `Blowfish` などの対称暗号化/復号化メソッドをリファクタリング、`cipher.NewXXXCipher()` で統一
- `RSA` などの非対称暗号化/復号化メソッドをリファクタリング、`keypair.NewXXXKeyPair()` で統一

::: details What's Changed (55)

- Update content by [@gouguoyin](https://github.com/gouguoyin) in [41dbddf](https://github.com/dromara/dongle/commit/41dbddfa1c9824f301bc44b433c767f5c6008ca4)
- Unified error handling by [@gouguoyin](https://github.com/gouguoyin) in [79209ec](https://github.com/dromara/dongle/commit/79209ec625fa175e50a137413ada6ab2f73cbadf)
- Update introduction by [@gouguoyin](https://github.com/gouguoyin) in [839738a](https://github.com/dromara/dongle/commit/839738ab7638bb4d6ec65384bcd2c5396c1f0841)
- Update references link by [@gouguoyin](https://github.com/gouguoyin) in [178ccbf](https://github.com/dromara/dongle/commit/178ccbfeb977be21cab055d24f74d4592876b1fe)
- build: Upgrade go and dependency library version by [@gouguoyin](https://github.com/gouguoyin) in [bd915fa](https://github.com/dromara/dongle/commit/bd915fae1421a9e634a545b1bd96ca8e808df0f0)
- chore: Delete unnecessary directories and files by [@gouguoyin](https://github.com/gouguoyin) in [4050bc9](https://github.com/dromara/dongle/commit/4050bc949a7eaa4d8b1e38dcc4da9ac04986d89a)
- feat(coding): Add streaming encoding and decoding for base32 by [@gouguoyin](https://github.com/gouguoyin) in [bd888e4](https://github.com/dromara/dongle/commit/bd888e4ebb6e9a013757bc2f2df5e8f50ffbada3)
- feat(coding): Refactor encoding and decoding for base32, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [3658c88](https://github.com/dromara/dongle/commit/3658c88825d917e42f85f5faf2af5dc1b7bf96c4)
- feat(coding): Refactor encoding and decoding for base45, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [4a9e5f1](https://github.com/dromara/dongle/commit/4a9e5f1bf58a10efe3276d73ddc4ece4994c01bf)
- feat(coding): Refactor encoding and decoding for base58, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [94af864](https://github.com/dromara/dongle/commit/94af8646dc560b2638ae3808e29edf338787b484)
- feat(coding): Refactor encoding and decoding for base62, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [ec8cf47](https://github.com/dromara/dongle/commit/ec8cf474dd79d779f2bcced81354b0813f16883f)
- feat(coding): Refactor encoding and decoding for base64, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [fab63f8](https://github.com/dromara/dongle/commit/fab63f81940b962c42c7fa4a4e7ef0e6fd6fe962)
- feat(coding): Refactor encoding and decoding for base85, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [12b8686](https://github.com/dromara/dongle/commit/12b86866e223e1f1251a232342df2b93f8b001b9)
- feat(coding): Refactor encoding and decoding for base91, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [6253df9](https://github.com/dromara/dongle/commit/6253df92ff3bcba0238d26ee1c2592b3c1aaa8a2)
- feat(coding): Refactor encoding and decoding for base100, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [7938084](https://github.com/dromara/dongle/commit/79380846b28c01c597f01d4b4efe2a2af52a9414)
- feat(coding): Refactor encoding and decoding for hex, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [90421f9](https://github.com/dromara/dongle/commit/90421f9bf438c3ee2c64e5eb1bd8b134a20f0077)
- feat(coding): Refactor encoding and decoding for morse, and added streaming support by [@gouguoyin](https://github.com/gouguoyin) in [e556a27](https://github.com/dromara/dongle/commit/e556a276964054a4adf1e761790c29eb64255ca2)
- test(coding): Add unit tests and examples for Base32 encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [49e8824](https://github.com/dromara/dongle/commit/49e88246b3671c5c10ae2317a21d137c9fecde54)
- test(coding): Add unit tests and examples for Base45 encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [8bb6af4](https://github.com/dromara/dongle/commit/8bb6af4efb395160fc5bac24f7e57362fa7dfbc6)
- test(coding): Add unit tests and examples for Base58 encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [9acead1](https://github.com/dromara/dongle/commit/9acead1be485a91074c0391587c53c578342ae0c)
- test(coding): Add unit tests and examples for Base62 encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [0e759d4](https://github.com/dromara/dongle/commit/0e759d4c3423cbd2866588cccd2348ce14562dc7)
- test(coding): Add unit tests and examples for Base64 encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [56b939f](https://github.com/dromara/dongle/commit/56b939fdbebb8301c951cc1096f36bb45112ff8e)
- test(coding): Add unit tests and examples for Base85 encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [e3c40d3](https://github.com/dromara/dongle/commit/e3c40d3edd6b0db8f1d341d518850cd8f3e74db1)
- test(coding): Add unit tests and examples for Base91 encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [581084d](https://github.com/dromara/dongle/commit/581084d5ec8554858333fcef65d56272abbf54e0)
- test(coding): Add unit tests and examples for Base100 encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [8a649aa](https://github.com/dromara/dongle/commit/8a649aabd75bfbadd43b75b7a9dd7b26b9f4d5f6)
- feat(coding): Add a universal decoder by [@gouguoyin](https://github.com/gouguoyin) in [56e267d](https://github.com/dromara/dongle/commit/56e267d039ae304cc10a4f6899fae15d2a886069)
- feat(coding): Add a universal encoder by [@gouguoyin](https://github.com/gouguoyin) in [df83e3d](https://github.com/dromara/dongle/commit/df83e3dec71f54527def91db483626b8ac4591ff)
- test(coding): Add Decoder unit test by [@gouguoyin](https://github.com/gouguoyin) in [c8cd146](https://github.com/dromara/dongle/commit/c8cd146d17df48084a1ac93ee0a9ba912d65842a)
- test(coding): Add Encoder unit test by [@gouguoyin](https://github.com/gouguoyin) in [9ffeeb2](https://github.com/dromara/dongle/commit/9ffeeb2ab8b1a77cb9b9750e0ac3b524e657a52a)
- test(coding): Add unit tests and examples for Hex encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [7f0ebed](https://github.com/dromara/dongle/commit/7f0ebed5c4b41cc2877f0f562bb1071cd50d2862)
- test(coding): Add unit tests and examples for Morse encoding and decoding by [@gouguoyin](https://github.com/gouguoyin) in [e090a75](https://github.com/dromara/dongle/commit/e090a75c208e59f138bd1a107746245c2a442498)
- feat(utils): Add string and byte slice conversion tools by [@gouguoyin](https://github.com/gouguoyin) in [3d8531a](https://github.com/dromara/dongle/commit/3d8531a2e35e94e785f9362c4a9bd7464c3fa6a8)
- feat: Create a dongle package and initialize the basic structure by [@gouguoyin](https://github.com/gouguoyin) in [be20106](https://github.com/dromara/dongle/commit/be201063ace30e386486bbece0684815871f01ae)
- test(mock): Add mock file implementation and related tests by [@gouguoyin](https://github.com/gouguoyin) in [4966d26](https://github.com/dromara/dongle/commit/4966d26ef1b04cb1f55aa76c3942b3ffa3ba9ab3)
- feat(hash): Reconstruct hash algorithm by [@gouguoyin](https://github.com/gouguoyin) in [a72d1b5](https://github.com/dromara/dongle/commit/a72d1b5787ad874cc31d6bb8f11f50b2be0d847e)
- feat(crypto): Reconstruct crypto algorithm by [@gouguoyin](https://github.com/gouguoyin) in [935cb7f](https://github.com/dromara/dongle/commit/935cb7f9b287b9be4e88fbda48d1f931eebdbc02)
- test: xxx_unit_test.go -> xxx_test.go by [@gouguoyin](https://github.com/gouguoyin) in [a015292](https://github.com/dromara/dongle/commit/a015292d8da271d5c0a46e5f00c03f29cab9edea)
- feat: Add a Hasher instance by [@gouguoyin](https://github.com/gouguoyin) in [421a980](https://github.com/dromara/dongle/commit/421a980861f595014c01d5bf94c9f5535b5ada57)
- build: Update the dependency version in `go.mod` by [@gouguoyin](https://github.com/gouguoyin) in [195b44c](https://github.com/dromara/dongle/commit/195b44cb9b11d6bb6b2a27b7513ba0cee0173b0e)
- docs: Add a Japanese README file by [@gouguoyin](https://github.com/gouguoyin) in [64b7b5c](https://github.com/dromara/dongle/commit/64b7b5c0373ab25ffdcebc909189f47751044254)
- build: Update import path by [@gouguoyin](https://github.com/gouguoyin) in [290a5d2](https://github.com/dromara/dongle/commit/290a5d233e9dab5bd6215ae44fe5fc9d5d2ad29b)
- docs: Update the code coverage badge link in the README file by [@gouguoyin](https://github.com/gouguoyin) in [918a4c7](https://github.com/dromara/dongle/commit/918a4c71117762151a3a2363915b69a7f3ca02dd)
- docs:HASH -> Hash, HMAC -> Hmac by [@gouguoyin](https://github.com/gouguoyin) in [bfe4ef9](https://github.com/dromara/dongle/commit/bfe4ef90d50fa10c2ecea0f0495931ec5e169fd2)
- refactor: Unify import sequence by [@gouguoyin](https://github.com/gouguoyin) in [1312eb8](https://github.com/dromara/dongle/commit/1312eb8f21e71a605dcd9259f128252c9413929e)
- refactor(rsa): Reconstruct signature and verification by [@gouguoyin](https://github.com/gouguoyin) in [f5bda3f](https://github.com/dromara/dongle/commit/f5bda3f1926c7ee10ee77e7e421b4281799fb297)
- refactor(crypto): Support streaming decryption by [@gouguoyin](https://github.com/gouguoyin) in [a3fdee1](https://github.com/dromara/dongle/commit/a3fdee1ef443d7b0f6a26f49484096c83c175c5f)
- docs(README): Update project documents and logo links by [@gouguoyin](https://github.com/gouguoyin) in [a7c712b](https://github.com/dromara/dongle/commit/a7c712be0fc486d025359be33b00977029388902)
- ci: Update workflow configuration and code coverage branch by [@gouguoyin](https://github.com/gouguoyin) in [1f09724](https://github.com/dromara/dongle/commit/1f0972468874d60810af435ef46eacea76823b0b)
- ci: Update workflow configuration by [@gouguoyin](https://github.com/gouguoyin) in [1956fbc](https://github.com/dromara/dongle/commit/1956fbc7ed0ba8e00c87913a2090978cdaece141)
- ci: Update code coverage branch by [@gouguoyin](https://github.com/gouguoyin) in [dfb63f6](https://github.com/dromara/dongle/commit/dfb63f6af6fa8ad7cc5d79a49053d58b9996957a)
- test: Remove utils/converter_example_test.go by [@gouguoyin](https://github.com/gouguoyin) in [17e9909](https://github.com/dromara/dongle/commit/17e99097b9e08df644f8b83a65c66ad6d2e00982)
- ci: Update the testing workflow to include all directories by [@gouguoyin](https://github.com/gouguoyin) in [f2c8a46](https://github.com/dromara/dongle/commit/f2c8a4627a7a47a64f8a9e0ba4a3aea852966505)
- feat: Add version number constant by [@gouguoyin](https://github.com/gouguoyin) in [f6f6061](https://github.com/dromara/dongle/commit/f6f6061d58f13c1413e691267a0b586eca487a60)
- docs(readme): Update the README file in multiple languages by [@gouguoyin](https://github.com/gouguoyin) in [28993a4](https://github.com/dromara/dongle/commit/28993a4f0d64b9faee6faec0b6f95ce326b6bb6c)
- docs: Update the project introduction in the README file by [@gouguoyin](https://github.com/gouguoyin) in [eb8def1](https://github.com/dromara/dongle/commit/eb8def1a655e76c4e2caa299654dd61ff8a952a7)

:::

## [v1.0.1](https://github.com/dromara/dongle/compare/v1.0.0...v1.0.1) (2024-11-22)

### ✨ 新機能

- `base62` カスタムエンコードテーブルをサポート

### 🐛 修正

- `AES-CBC-PKCS5` 暗号化復号化エラーのBugを修正

### 🔧 リファクタリング

- コード品質と組織構造を最適化
- `errors.go` ファイルを削除、エラー情報を各ファイルに移行
- 単体テストフォーマットを統一
- 中文コメントを削除

::: details What's Changed (22)

- Changed badge url by [@gouguoyin](https://github.com/gouguoyin) in [5f1a726](https://github.com/dromara/dongle/commit/5f1a726c244677533a08ada210696315a5715026)
- update by [@gouguoyin](https://github.com/gouguoyin) in [2703673](https://github.com/dromara/dongle/commit/2703673410bd0ad4370e326d97d4a014ac6ef200)
- Changed badge address by [@gouguoyin](https://github.com/gouguoyin) in [343a3c2](https://github.com/dromara/dongle/commit/343a3c25845aab6fed4c93695569cbbb4da733f9)
- 修改徽章地址 by [@gouguoyin](https://github.com/gouguoyin) in [0a934f5](https://github.com/dromara/dongle/commit/0a934f54da1f778828ad34b6baa0f543e74b01e7)
- Unified Unit test Format by [@gouguoyin](https://github.com/gouguoyin) in [09b1657](https://github.com/dromara/dongle/commit/09b1657fcbdae30d09309b5732341201d32b7e5e)
- Bump codecov/codecov-action from 4 to 5 by [@gouguoyin](https://github.com/gouguoyin) in [cee97bf](https://github.com/dromara/dongle/commit/cee97bf91b1e8bf91e104e3c69a825fef9ce7d09)
- Support custom alphabet table by [@gouguoyin](https://github.com/gouguoyin) in [3d21a8e](https://github.com/dromara/dongle/commit/3d21a8e8273dcae48e7aba209a3f4b904d140ed6)
- Support custom alphabet table for base62 by [@gouguoyin](https://github.com/gouguoyin) in [e53528a](https://github.com/dromara/dongle/commit/e53528a44cd50d0915d0efdb3b49bdb7b33d122f)
- Remove benchmark file by [@gouguoyin](https://github.com/gouguoyin) in [77fb897](https://github.com/dromara/dongle/commit/77fb89755a52908639555c4881cb45346271fb40)
- Remove errors from errors.go to the current file by [@gouguoyin](https://github.com/gouguoyin) in [c286a54](https://github.com/dromara/dongle/commit/c286a5489c4abd9342091a4a6023a858d661ead0)
- Remove Chinese annotations by [@gouguoyin](https://github.com/gouguoyin) in [c969116](https://github.com/dromara/dongle/commit/c96911696c7c15f2551e47b7ec43d58a2a8b066c)
- Change key type from `interface{}` to `[]byte` by [@gouguoyin](https://github.com/gouguoyin) in [1f43106](https://github.com/dromara/dongle/commit/1f43106d759e94c870c8488f73146f74359940cb)
- Change privateKey and publicKey type from `interface{}` to `[]byte` by [@gouguoyin](https://github.com/gouguoyin) in [d92e678](https://github.com/dromara/dongle/commit/d92e6780eb9f834f3d8603e869e8fe08b0e7b640)
- Upgrade version by [@gouguoyin](https://github.com/gouguoyin) in [7afcd5e](https://github.com/dromara/dongle/commit/7afcd5e48d0991b1edb84a03a767b94d53d2b526)
- github.com/golang-module/dongle -> github.com/dromara/dongle by [@gouguoyin](https://github.com/gouguoyin) in [34d2c49](https://github.com/dromara/dongle/commit/34d2c49c2897562f9faaf24f8ef84882460382db)
- Add `WithKey` and `WithIV` methods by [@gouguoyin](https://github.com/gouguoyin) in [fdef30b](https://github.com/dromara/dongle/commit/fdef30b3b517a9988aa6f334eb8950b5cc8220d1)
- Remove github.com/golang-module/dongle by [@gouguoyin](https://github.com/gouguoyin) in [42685d4](https://github.com/dromara/dongle/commit/42685d421861ea94ca043601603d288a97e3148d)
- Remove errors.go by [@gouguoyin](https://github.com/gouguoyin) in [f0b67fb](https://github.com/dromara/dongle/commit/f0b67fb107547782c0cd96385ceb7a36dc4b7a75)
- Update content about `base62` by [@gouguoyin](https://github.com/gouguoyin) in [3623058](https://github.com/dromara/dongle/commit/3623058e26bd5a49d7871ecd2bfdac42d071342a)
- Update content by [@gouguoyin](https://github.com/gouguoyin) in [4a68d5f](https://github.com/dromara/dongle/commit/4a68d5f9e90aec8e7ecdd77ad5e4eca320a344d9)
- Upgrade version to `1.0.1` by [@gouguoyin](https://github.com/gouguoyin) in [f81202d](https://github.com/dromara/dongle/commit/f81202d3f0fb9b88994754808c58b2cb0d016c74)
- Remove useless type conversions by [@gouguoyin](https://github.com/gouguoyin) in [42d5ae3](https://github.com/dromara/dongle/commit/42d5ae330fcee5def1fcee4e7e98e01688192002)

:::

## [v1.0.0](https://github.com/dromara/dongle/compare/v0.2.8...v1.0.0) (2024-11-11)

### 🐛 修正

- AES/ECB/PKCS5 パディングによる panic を修正

### 📝 ドキュメント

- リポジトリとバッジURLを変更

::: details What's Changed (5)

- Fixed: AES/ECB/PCKS5padding panic by xiaoyiyu in [5497c86](https://github.com/dromara/dongle/commit/5497c86db771cba55d9bf161251c1b3b531f8a7b)
- Update content by [@gouguoyin](https://github.com/gouguoyin) in [f009269](https://github.com/dromara/dongle/commit/f0092693b9704ffc9b57c6180f552404b4864ad7)
- Upgrade version by [@gouguoyin](https://github.com/gouguoyin) in [3293d42](https://github.com/dromara/dongle/commit/3293d4225c7be7e1b62921a5e96b8b1219a89064)
- golang-module/dongle->dromara/dongle by [@gouguoyin](https://github.com/gouguoyin) in [de7c99b](https://github.com/dromara/dongle/commit/de7c99ba9220f68a285c0852881a0491832e0e17)
- Changed badge url by [@gouguoyin](https://github.com/gouguoyin) in [50691b6](https://github.com/dromara/dongle/commit/50691b6d40e6cbce397e3ede4c3b962ca2224f51)

:::

より古いバージョンの更新ログについては、<a href="https://github.com/dromara/dongle/releases" target="_blank" rel="noreferrer">releases</a> を参照してください
