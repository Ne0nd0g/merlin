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

// Package base64 encodes/decodes Agent messages
package base64

import (
	"encoding/base64"
	"fmt"
)

const (
	BYTE   = 0
	STRING = 1
)

type Coder struct {
	concrete int
}

// NewEncoder is a factory that returns a structure that implements the Transformer interface
func NewEncoder(concrete int) *Coder {
	return &Coder{concrete: concrete}
}

// Construct takes in data, Base64 encodes it, and returns the encoded data as bytes
func (c *Coder) Construct(data any, key []byte) (retData []byte, err error) {
	switch c.concrete {
	case BYTE:
		retData = make([]byte, base64.StdEncoding.EncodedLen(len(data.([]byte))))
		base64.StdEncoding.Encode(retData, data.([]byte))
	case STRING:
		retData = []byte(base64.StdEncoding.EncodeToString(data.([]byte)))
	}
	return
}

// Deconstruct takes in bytes and Base64 decodes it to its original type
func (c *Coder) Deconstruct(data, key []byte) (any, error) {
	switch c.concrete {
	case BYTE:
		retData := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		return base64.StdEncoding.Decode(retData, data)
	case STRING:
		return base64.StdEncoding.DecodeString(string(data))
	default:
		return nil, fmt.Errorf("transformer/encoders/base64.Deconstruct(): unhandled concrete type %d", c.concrete)
	}
}

// String converts the Gob encode/decode constant to a string
func (c *Coder) String() string {
	switch c.concrete {
	case BYTE:
		return "base64-byte"
	case STRING:
		return "base64-string"
	default:
		return fmt.Sprintf("unknown base64 transform %d", c.concrete)
	}
}
