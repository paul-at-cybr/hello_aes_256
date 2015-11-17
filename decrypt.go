/**
 * Adapted from godoc example:
 * https://golang.org/src/crypto/cipher/example_test.go
 */

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"fmt"
)

var (
	key            = ""
	encryptedValue = ""
)

func init() {
	// prepare commandline variables
	flag.StringVar(&key, "key", "xohlfirdt498grlyjc3746nhowlgpx8p", "decryption key")
	flag.StringVar(&encryptedValue, "val", "", "value to decrypt")
}

func main() {
	flag.Parse() // parse commandline variables

	// translate key to cipher
	bkey := []byte(key)
	block, err := aes.NewCipher(bkey)
	if err != nil {
		panic(err)
	}

	// decode base64-encoded string to byteslice
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		panic(err)
	}

	// make sure the cipher matches the block size
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}

	// get the iv (first 128 bits of the encrypted string)
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:] // get the rest for decryption

	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	fmt.Printf("%s\n", ciphertext)
}
