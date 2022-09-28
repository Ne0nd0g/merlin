package util

import (
	// Standard
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/core"
)

// AESEncrypt reads in plaintext data as aa byte slice, encrypts it with the client's secret key, and returns the ciphertext
func AESEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	if core.Debug {
		message("debug", "Entering into AESEncrypt")
		message("debug", fmt.Sprintf("Plaintext: %s", plaintext))
	}

	// Pad plaintext
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext = append(plaintext, padtext...)

	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext size: %d is not a multiple of the block size: %d", len(plaintext), aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// AES CBC Encrypt
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// HMAC
	hash := hmac.New(sha256.New, key)
	_, err = hash.Write(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("there was an error in the aesEncrypt function writing the HMAC:\r\n%s", err)
	}

	// IV + Ciphertext + HMAC
	return append(ciphertext, hash.Sum(nil)...), nil
}

// AESDecrypt reads in ciphertext data as a byte slice, decrypts it with the client's secret key, and returns the plaintext
func AESDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if core.Debug {
		message("debug", "Entering into AESDecrypt()...")
	}

	var block cipher.Block
	var err error

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext was not greater than the AES block size")
	}

	// IV + Ciphertext + HMAC
	iv := ciphertext[:aes.BlockSize]
	hash := ciphertext[len(ciphertext)-32:]
	ciphertext = ciphertext[aes.BlockSize : len(ciphertext)-32]

	// Verify encrypted data is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext was not a multiple of the AES block size")
	}

	// Verify the HMAC hash
	h := hmac.New(sha256.New, key)
	_, err = h.Write(append(iv, ciphertext...))
	if err != nil {
		return nil, fmt.Errorf("there was an error in the aesDecrypt function writing the HMAC:\r\n%s", err)
	}
	if !hmac.Equal(h.Sum(nil), hash) {
		return nil, fmt.Errorf("there was an error validating the AES HMAC hash, expected: %x but got: %x", h.Sum(nil), hash)
	}

	// AES CBC Decrypt
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	// Remove padding
	ciphertext = ciphertext[:(len(ciphertext) - int(ciphertext[len(ciphertext)-1]))]

	return ciphertext, nil
}
