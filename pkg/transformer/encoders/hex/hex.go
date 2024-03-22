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

// Package hex encodes/decodes Agent messages
package hex

import (
	"encoding/hex"
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

// Construct takes in data, hex encodes it, and returns the encoded data as bytes
func (c *Coder) Construct(data any, key []byte) (retData []byte, err error) {
	switch c.concrete {
	case BYTE:
		retData = make([]byte, hex.EncodedLen(len(data.([]byte))))
		hex.Encode(retData, data.([]byte))
	case STRING:
		retData = []byte(hex.EncodeToString(data.([]byte)))
	default:
		err = fmt.Errorf("transformer/encoders/hex.Construct(): unhandled concrete type: %d", c.concrete)
	}
	return
}

// Deconstruct takes in bytes and hex decodes it to its original type
func (c *Coder) Deconstruct(data, key []byte) (any, error) {
	retData := make([]byte, hex.DecodedLen(len(data)))
	_, err := hex.Decode(retData, data)
	if err != nil {
		return nil, fmt.Errorf("transformer/encoders/hex.Deconstruct(): there was an error Base64 decoding the incoming data: %s", err)
	}
	switch c.concrete {
	case BYTE:
		return retData, nil
	case STRING:
		return string(retData), nil
	default:
		return nil, fmt.Errorf("transformer/encoders/hex.Deconstruct(): unhandled concrete type %d", c.concrete)
	}
}

// String converts the Gob encode/decode constant to a string
func (c *Coder) String() string {
	switch c.concrete {
	case BYTE:
		return "hex-byte"
	case STRING:
		return "hex-string"
	default:
		return fmt.Sprintf("hex base64 transform %d", c.concrete)
	}
}
