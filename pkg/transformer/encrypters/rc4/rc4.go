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

// Package rc4 encrypts/decrypts Agent messages
package rc4

import (
	"crypto/rc4" // #nosec G503 Intentionally using RC4 knowing it is insecure
	"fmt"
)

type Encrypter struct {
}

// NewEncrypter is a factory to return a structure that implements the Transformer interface
func NewEncrypter() *Encrypter {
	return &Encrypter{}
}

// Construct takes data in data, RC4 encrypts it with the provided key, and returns that data as bytes
func (e *Encrypter) Construct(data any, key []byte) (retData []byte, err error) {

	switch data.(type) {
	case []uint8:
		return xor(data.([]byte), key)
	default:
		return nil, fmt.Errorf("pkg/encrypters/rc4 unhandled data type for Construct(): %T", data)
	}
}

// Deconstruct takes in RC4 encrypted data, decrypts it with the provided key, and returns the data as bytes
func (e *Encrypter) Deconstruct(data, key []byte) (any, error) {
	return xor(data, key)
}

func xor(data, key []byte) (retData []byte, err error) {
	retData = make([]byte, len(data))
	cipher, err := rc4.NewCipher(key) // #nosec G401 Intentionally using RC4 knowing it is insecure
	if err != nil {
		return []byte{}, fmt.Errorf("pkg/transformer/encrypters/rc4.Construct(): there was an error getting an RC4 cipher: %s", err)
	}
	cipher.XORKeyStream(retData, data)
	return
}

func (e *Encrypter) String() string {
	return "rc4"
}
