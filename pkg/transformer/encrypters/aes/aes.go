/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

// Package aes encrypts/decrypts Agent messages
package aes

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
)

type Encrypter struct {
}

// NewEncrypter is a factory to return a structure that implements the Transformer interface
func NewEncrypter() *Encrypter {
	return &Encrypter{}
}

// Construct takes data in data, AES encrypts it with the provided key, and returns that data as bytes
func (e *Encrypter) Construct(data any, key []byte) ([]byte, error) {
	switch data.(type) {
	case []uint8:
		return encrypt(data.([]byte), key)
	default:
		return nil, fmt.Errorf("pkg/encrypters/aes unhandled data type for Construct(): %T", data)
	}
}

// Deconstruct takes in AES encrypted data, decrypts it with the provided key, and returns the data as bytes
func (e *Encrypter) Deconstruct(data, key []byte) (any, error) {
	return decrypt(data, key)
}

// encrypt reads in plaintext data as aa byte slice, encrypts it with the client's secret key, and returns the ciphertext
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Pad plaintext
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext = append(plaintext, padtext...)

	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext size: %d is not a multiple of the block size: %d", len(plaintext), aes.BlockSize)
	}

	// AES only takes 16, 24, or 32 byte keys
	if len(key) > 32 {
		temp := sha256.Sum256(key)
		key = temp[:]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pkg/encrypters/aes.encrypt(): %s", err)
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

// decrypt reads in ciphertext data as a byte slice, decrypts it with the client's secret key, and returns the plaintext
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	var block cipher.Block
	var err error

	// AES only takes 16, 24, or 32 byte keys
	if len(key) > 32 {
		temp := sha256.Sum256(key)
		key = temp[:]
	}

	if block, err = aes.NewCipher(key); err != nil {
		return nil, fmt.Errorf("pkg/encrypters/aes.decrypt(): %s", err)
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

func (e *Encrypter) String() string {
	return "aes"
}
