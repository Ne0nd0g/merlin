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

// Package xor encrypts/decrypts Agent messages
package xor

import (
	"fmt"
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
		return xor(data.([]byte), key)
	default:
		return nil, fmt.Errorf("pkg/encrypters/aes unhandled data type for Construct(): %T", data)
	}
}

// Deconstruct takes in AES encrypted data, decrypts it with the provided key, and returns the data as bytes
func (e *Encrypter) Deconstruct(data, key []byte) (any, error) {
	return xor(data, key)
}

func xor(data, key []byte) (retData []byte, err error) {
	retData = make([]byte, len(data))
	for k, v := range data {
		retData[k] = v ^ key[k%len(key)]
	}
	return
}

func (e *Encrypter) String() string {
	return "xor"
}
