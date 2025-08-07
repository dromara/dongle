// @Package dongle
// @Description a simple, semantic and developer-friendly golang crypto package
// @Page github.com/dromara/dongle
// @Developer gouguoyin
// @Email 245629560@qq.com

// Package dongle is a simple, semantic and developer-friendly golang crypto package.
package dongle

import (
	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/crypto"
)

var (
	// Encode defines an Encoder instance.
	Encode = coding.NewEncoder()
	// Decode defines a Decoder instance.
	Decode = coding.NewDecoder()

	// Encrypt defines an Encrypter instance.
	Encrypt = crypto.NewEncrypter()
	// Decrypt defines a Decrypter instance.
	Decrypt = crypto.NewDecrypter()

	// Sign defines a Signer instance.
	Sign = crypto.NewSigner()
	// Verify defines a Verifier instance.
	Verify = crypto.NewVerifier()
)
