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

// Package jwe encrypts/decrypts Agent messages to/from JSON Web Encryption compact serialization format
package jwe

import (
	// Standard
	"fmt"

	// 3rd Party
	"github.com/go-jose/go-jose/v3"
)

type Encrypter struct {
}

// NewEncrypter is a factory to return a structure that implements the Transformer interface
func NewEncrypter() *Encrypter {
	return &Encrypter{}
}

// Construct takes data in data, encrypts it using PBES2 (RFC 2898) with HMAC SHA-512 as the PRF and
// AES Key Wrap (RFC 3394) using 256-bit keys for the encryption scheme. The data is then transformed into a
// JSON Web Encryption (JWE) object and serializes it using the compact serialization format to string that is returned
// as bytes.
// PBES2 uses Password-Based Key Derivation Function 2 (PBKDF2) with a hard-coded 3000 rounds (iterations)
func (e *Encrypter) Construct(data any, key []byte) ([]byte, error) {
	switch data.(type) {
	case []uint8:
		return e.encrypt(data.([]byte), key)
	default:
		return nil, fmt.Errorf("pkg/encrypters/jwe unhandled data type for Construct(): %T", data)
	}
}

// Deconstruct takes in a JSON Web Encryption (JWE) object in the compact serialization format as bytes, decrypts it,
// and returns it that data as bytes
func (e *Encrypter) Deconstruct(data, key []byte) (any, error) {
	// Parse JWE string back into JSONWebEncryption
	jwe, err := jose.ParseEncrypted(string(data))
	if err != nil {
		return nil, fmt.Errorf("there was an error parseing the JWE string into a JSONWebEncryption object: %s", err)
	}

	// Decrypt the JWE
	return jwe.Decrypt(key)
}

// encrypt takes data in data, encrypts it using PBES2 (RFC 2898) with HMAC SHA-512 as the PRF and
// AES Key Wrap (RFC 3394) using 256-bit keys for the encryption scheme. The data is then transformed into a
// JSON Web Encryption (JWE) object and serializes it using the compact serialization format to string that is returned
// as bytes.
// PBES2 uses Password-Based Key Derivation Function 2 (PBKDF2) with a hard-coded 3000 rounds (iterations)
func (e *Encrypter) encrypt(data, key []byte) ([]byte, error) {
	//   Keys used with AES GCM must follow the constraints in Section 8.3 of
	//   [NIST.800-38D], which states: "The total number of invocations of the
	//   authenticated encryption function shall not exceed 2^32, including
	//   all IV lengths and all instances of the authenticated encryption
	//   function with the given key".  In accordance with this rule, AES GCM
	//   MUST NOT be used with the same key value more than 2^32 times. == 4294967296

	enc, err := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.PBES2_HS512_A256KW, // Creates a per message key encrypted with the passed in key
			//Algorithm: jose.DIRECT, // Doesn't create a per message key
			// https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2
			// A minimum iteration count of 1000 is RECOMMENDED.
			PBES2Count: 3000,
			Key:        key},
		nil)
	if err != nil {
		return nil, fmt.Errorf("there was an error creating the JWE encryptor:\r\n%s", err)
	}

	// Encrypt the data into a JWE
	jwe, err := enc.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("there was an error encrypting the Authentication JSON object to a JWE object:\r\n%s", err)
	}

	// Serialize the data into a string
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("there was an error serializing the JWE in compact format:\r\n%s", err)
	}

	// Parse it to make sure there were no errors serializing it
	_, err = jose.ParseEncrypted(serialized)
	if err != nil {
		return nil, fmt.Errorf("there was an error parsing the encrypted JWE:\r\n%s", err)
	}

	return []byte(serialized), nil
}

// String returns a string representation of the encrypter type
func (e *Encrypter) String() string {
	return "jwe"
}
