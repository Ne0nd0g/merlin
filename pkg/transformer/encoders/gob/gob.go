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

// Package gob encodes/decodes Agent messages
package gob

import (
	// Standard
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"log/slog"

	// Merlin Message
	"github.com/Ne0nd0g/merlin-message"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
)

const (
	STRING   = 0
	BASE     = 1
	DELEGATE = 2
)

type Coder struct {
	concrete int
}

// NewEncoder is a factory that returns a structure that implements the Transformer interface
func NewEncoder(concrete int) *Coder {
	return &Coder{concrete: concrete}
}

// Construct takes in data, Gob encodes it, and returns the encoded data as bytes
func (c *Coder) Construct(data any, key []byte) ([]byte, error) {
	return c.Encode(data)
}

// Deconstruct takes in bytes and Gob decodes it to its original type
func (c *Coder) Deconstruct(data, key []byte) (any, error) {
	return c.Decode(data)
}

// Encode takes in data, Gob encodes it, and returns the encoded data as bytes
// This function is exported so that it can be called directly outside the Transformer interface
func (c *Coder) Encode(e any) ([]byte, error) {
	//fmt.Printf("pkg/encoders/gob.Encode(): %T:%+v\n", e, e)
	encoded := new(bytes.Buffer)

	switch c.concrete {
	case BASE:
		data := e.(messages.Base)
		err := gob.NewEncoder(encoded).Encode(data)
		if err != nil {
			return nil, fmt.Errorf("pkg/encoders/gob.Encode(): error gob encoding messages.Base: %s", err)
		}
		return encoded.Bytes(), nil
	case STRING:
		data := string(e.([]byte))
		err := gob.NewEncoder(encoded).Encode(data)
		if err != nil {
			return nil, fmt.Errorf("pkg/encoders/gob.Encode(): error gob encoding string: %s", err)
		}
		return encoded.Bytes(), nil
	case DELEGATE:
		data := e.(messages.Delegate)
		err := gob.NewEncoder(encoded).Encode(data)
		if err != nil {
			return nil, fmt.Errorf("pkg/encoders/gob.Encode(): error gob encoding messages.Delegate: %s", err)
		}
		return encoded.Bytes(), nil
	default:
		return nil, fmt.Errorf("pkg/encoders/gob.Encode(): unhandled concrete type %T", c.concrete)
	}
}

// Decode takes in bytes and Gob decodes it to its original type
// This function is exported so that it can be called directly outside the Transformer interface
func (c *Coder) Decode(data []byte) (any, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "data length", len(data), "concrete type", fmt.Sprintf("%d", c.concrete))
	//fmt.Printf("Gob Decode %T concrete: %d\n", data, c.concrete)
	var err error
	switch c.concrete {
	case STRING:
		var d string
		err = gob.NewDecoder(bytes.NewReader(data)).Decode(&d)
		if err != nil {
			slog.Error("there was an error gob decoding the 'string' type", "error", err)
		}
		return d, err
	case BASE:
		var d messages.Base
		err = gob.NewDecoder(bytes.NewReader(data)).Decode(&d)
		if err != nil {
			slog.Error("there was an error gob decoding the 'BASE' type", "error", err)
		}
		return d, err
	case DELEGATE:
		var d messages.Delegate
		err = gob.NewDecoder(bytes.NewReader(data)).Decode(&d)
		if err != nil {
			slog.Error("there was an error gob decoding the 'DELEGATE' type", "error", err)
		}
		return d, err
	default:
		return nil, fmt.Errorf("pkg/gob/encoders.Decode(): unhandled concrete type %d", c.concrete)
	}
}

// String converts the Gob encode/decode constant to a string
func (c *Coder) String() string {
	switch c.concrete {
	case STRING:
		return "gob-string"
	case BASE:
		return "gob-base"
	case DELEGATE:
		return "gob-delegate"
	default:
		return fmt.Sprintf("unknown gob transform %d", c.concrete)
	}
}
